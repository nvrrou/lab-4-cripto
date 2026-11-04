FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server tcpdump ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash alumno \
    && mkdir -p /run/sshd /etc/ssh/host_keys \
    && rm -f /etc/ssh/ssh_host_*
COPY ssh/sshd_config /etc/ssh/sshd_config
COPY ssh/entrypoint.sh /usr/local/bin/lab-entrypoint
RUN chmod 755 /usr/local/bin/lab-entrypoint
EXPOSE 22
ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
