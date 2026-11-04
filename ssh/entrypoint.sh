#!/bin/sh
set -eu
mkdir -p /run/sshd /etc/ssh/host_keys
if [ ! -f /etc/ssh/host_keys/ssh_host_ed25519_key ]; then
    ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/host_keys/ssh_host_ed25519_key
fi
install -d -m 700 -o alumno -g alumno /home/alumno/.ssh
install -m 600 -o alumno -g alumno /tmp/cliente.pub /home/alumno/.ssh/authorized_keys
/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
