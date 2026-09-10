# Minimal, self-contained OpenLDAP directory for the OpsWarden lab.
# Built rather than pulled: the maintained public images are either stale or gated, and baking
# the sudo schema + seed data in keeps the directory reproducible and reviewable.
FROM debian:12-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      slapd ldap-utils libsasl2-modules ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*

COPY schema/sudo.ldif   /opt/openldap/schema/sudo.ldif
COPY seed/              /opt/openldap/seed/
COPY entrypoint.sh      /opt/openldap/entrypoint.sh
RUN chmod +x /opt/openldap/entrypoint.sh

# 389 = LDAP/STARTTLS, 636 = LDAPS
EXPOSE 389 636
VOLUME ["/var/lib/ldap", "/etc/ldap/slapd.d"]

ENTRYPOINT ["/opt/openldap/entrypoint.sh"]
