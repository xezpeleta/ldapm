FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils \
 && rm -rf /var/lib/apt/lists/*
COPY config.ldif gen-data.sh entrypoint.sh /seed/
RUN chmod +x /seed/*.sh
EXPOSE 389 636
ENTRYPOINT ["/seed/entrypoint.sh"]
