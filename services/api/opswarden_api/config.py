from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPSWARDEN_", env_file=".env", extra="ignore")

    # Read-only Elasticsearch (for the agent's tools / post-checks)
    es_url: str = "https://localhost:9200"
    es_user: str = "opswarden-reader"
    es_password: str = ""
    es_ca_cert: str | None = None

    # Ansible execution
    ansible_dir: str = "ansible"            # relative to repo root or absolute
    ansible_config: str | None = None       # cfg filename under ansible_dir (cluster mode)
    playbook_timeout: int = 1800

    # Persistence (proposals + LangGraph checkpoints)
    db_path: str = "opswarden.db"
    base_url: str = "http://localhost:8080"

    # Claude via Vertex AI (optional; falls back to a deterministic narrative if unset)
    vertex_project: str | None = None
    vertex_region: str = "us-east5"
    claude_model: str = "claude-opus-5"
    llm_timeout_seconds: float = 45.0

    # Slack (optional; falls back to the built-in approval UI)
    slack_webhook_url: str | None = None
    slack_bot_token: str | None = None
    slack_signing_secret: str | None = None

    # ServiceNow PDI (optional; falls back to a local ticket store)
    servicenow_instance: str | None = None   # e.g. dev12345
    servicenow_user: str | None = None
    servicenow_password: str | None = None
    # Optional OAuth (Application Registry "OAuth API endpoint for external clients").
    # When set, a bearer token is obtained via the password grant instead of basic auth.
    servicenow_client_id: str | None = None
    servicenow_client_secret: str | None = None
    servicenow_scope: str = "useraccount"
    servicenow_close_code: str = "Solution provided"

    # --- authentication / authorisation ---
    session_secret: str = ""                 # signs session cookies (required)
    session_max_age: int = 8 * 3600
    cookie_secure: bool = False   # True behind TLS/ingress
    ingest_token: str = ""                   # shared secret for the detector's POST /events
    ldap_host: str = "openldap.identity.svc.cluster.local"
    ldap_port: int = 389
    ldap_base_dn: str = "dc=opswarden,dc=internal"
    ldap_ca_cert: str | None = None          # path; when set, StartTLS with verification
    approver_group: str = "sysadmins"        # LDAP group permitted to approve

    # --- event de-duplication ---
    dedup_window_minutes: int = 30           # suppress repeats of an already-open event


@lru_cache
def get_settings() -> Settings:
    """Single settings instance, injected via Depends so tests can override it."""
    return Settings()
