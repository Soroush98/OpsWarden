"""Authentication and authorisation.

Humans authenticate against the same LDAP directory the agent administers, which means the
approver identity on an audit record is a verified directory bind, not a string the caller typed.
Authorisation is a group check: only members of the approver group may approve or reject.

Machines (the detector) present a shared ingest token instead; they may submit events but can
never approve one.
"""
from __future__ import annotations

import hmac
import logging
import ssl
from dataclasses import dataclass

import ldap3
from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from opswarden_api.config import Settings, get_settings

log = logging.getLogger("opswarden.auth")

SESSION_COOKIE = "opswarden_session"


@dataclass(frozen=True)
class User:
    username: str
    groups: tuple[str, ...]

    def in_group(self, group: str) -> bool:
        return group in self.groups


class AuthError(Exception):
    """Credentials were rejected."""


def _serializer(s: Settings) -> URLSafeTimedSerializer:
    if not s.session_secret:
        raise RuntimeError("OPSWARDEN_SESSION_SECRET is not set; refusing to run without it")
    return URLSafeTimedSerializer(s.session_secret, salt="opswarden-session")


def _ldap_server(s: Settings) -> ldap3.Server:
    tls = None
    if s.ldap_ca_cert:
        tls = ldap3.Tls(ca_certs_file=s.ldap_ca_cert, validate=ssl.CERT_REQUIRED)
    return ldap3.Server(s.ldap_host, port=s.ldap_port, use_ssl=False, tls=tls, get_info=None)


def authenticate(username: str, password: str, s: Settings) -> User:
    """Bind to LDAP as the user, then read their group membership. Raises AuthError."""
    if not username or not password:
        raise AuthError("username and password are required")
    user_dn = f"uid={ldap3.utils.conv.escape_filter_chars(username)},ou=people,{s.ldap_base_dn}"
    conn = None
    try:
        conn = ldap3.Connection(_ldap_server(s), user=user_dn, password=password,
                                auto_bind=False, receive_timeout=10)
        if s.ldap_ca_cert:
            conn.open()
            conn.start_tls()
        if not conn.bind():
            raise AuthError("invalid credentials")
        safe = ldap3.utils.conv.escape_filter_chars(username)
        conn.search(f"ou=groups,{s.ldap_base_dn}",
                    f"(&(objectClass=posixGroup)(memberUid={safe}))",
                    attributes=["cn"])
        groups = tuple(str(e["cn"]) for e in conn.entries)
        return User(username=username, groups=groups)
    except AuthError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning("LDAP authentication error for %r: %s", username, exc)
        raise AuthError("directory unavailable or credentials rejected") from exc
    finally:
        if conn is not None:
            try:
                conn.unbind()
            except Exception:  # noqa: BLE001, S110
                pass


def issue_session(user: User, s: Settings) -> str:
    return _serializer(s).dumps({"u": user.username, "g": list(user.groups)})


def read_session(token: str, s: Settings) -> User | None:
    try:
        data = _serializer(s).loads(token, max_age=s.session_max_age)
    except (BadSignature, SignatureExpired):
        return None
    return User(username=data.get("u", ""), groups=tuple(data.get("g", [])))


def current_user(request: Request, s: Settings = Depends(get_settings)) -> User | None:
    token = request.cookies.get(SESSION_COOKIE)
    return read_session(token, s) if token else None


def require_user(user: User | None = Depends(current_user)) -> User:
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail={"code": "unauthenticated", "message": "sign in required"})
    return user


def require_approver(user: User = Depends(require_user),
                     s: Settings = Depends(get_settings)) -> User:
    """Authentication is not authorisation: approving requires the approver group."""
    if not user.in_group(s.approver_group):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "not_an_approver",
                    "message": f"approval requires membership of '{s.approver_group}'"})
    return user


def require_ingest_token(request: Request, s: Settings = Depends(get_settings)) -> None:
    """Machine callers (the detector) may submit events, nothing else."""
    if not s.ingest_token:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail={"code": "ingest_disabled", "message": "no ingest token configured"})
    presented = request.headers.get("x-opswarden-token", "")
    if not hmac.compare_digest(presented, s.ingest_token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail={"code": "bad_token", "message": "invalid ingest token"})
