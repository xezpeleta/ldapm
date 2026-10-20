FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/sh tunnel && mkdir -p /run/sshd /home/tunnel/.ssh \
 && printf 'PasswordAuthentication no\nAllowTcpForwarding yes\nPermitTTY no\nX11Forwarding no\n' > /etc/ssh/sshd_config.d/ldapm.conf
CMD ["/bin/sh", "-c", "install -o tunnel -m 600 /keys/bastion_ed25519.pub /home/tunnel/.ssh/authorized_keys && exec /usr/sbin/sshd -D -e"]
