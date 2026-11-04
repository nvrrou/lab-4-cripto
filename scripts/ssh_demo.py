#!/usr/bin/env python3
"""Construye SSH, captura una conexión real y guarda evidencias reproducibles."""
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
DC = ['docker', 'compose']


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, text=True, **kwargs)


def main():
    os.chdir(ROOT)
    local = ROOT / '.local'
    local.mkdir(exist_ok=True, mode=0o700)
    # Una carpeta por ejecución evita confundir una captura anterior con la actual.
    evidence = ROOT / 'evidencias' / time.strftime('ssh-%Y%m%d-%H%M%S')
    evidence.mkdir(parents=True)
    key = local / 'id_ed25519'
    if not key.exists():
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
    with (evidence / '01-build.log').open('w') as log:
        run(DC + ['build', '--progress=plain'], stdout=log, stderr=subprocess.STDOUT)
    run(DC + ['up', '-d', '--wait'])
    (evidence / '02-contenedor.txt').write_text(run(DC + ['ps'], capture_output=True).stdout)
    config = run(DC + ['exec', '-T', 'ssh', '/usr/sbin/sshd', '-T'], capture_output=True).stdout
    (evidence / '03-sshd-efectivo.txt').write_text(config)
    expected = ['kexalgorithms curve25519-sha256', 'ciphers aes256-ctr',
                'macs hmac-sha2-256', 'hostkeyalgorithms ssh-ed25519']
    for setting in expected:
        if setting not in config.splitlines():
            raise RuntimeError(f'Configuración incorrecta: {setting}')
    pub = run(DC + ['exec', '-T', 'ssh', 'cat', '/etc/ssh/host_keys/ssh_host_ed25519_key.pub'],
              capture_output=True).stdout.split()
    known = local / 'known_hosts'
    known.write_text(f'[127.0.0.1]:2222 {pub[0]} {pub[1]}\n')
    run(DC + ['exec', '-T', '-d', 'ssh', 'sh', '-c',
              'echo $$ > /tmp/lab-capture.pid; exec tcpdump --immediate-mode -U -i any -w /tmp/lab-ssh.pcap "tcp port 22" > /tmp/lab-capture.log 2>&1'])
    try:
        for _ in range(30):
            ready = run(DC + ['exec', '-T', 'ssh', 'cat', '/tmp/lab-capture.log'], capture_output=True).stdout
            if 'listening on' in ready:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(f'No comenzó la captura: {ready}')
        ssh = ['ssh', '-F', '/dev/null', '-vvv', '-p', '2222', '-i', str(key),
               '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
               '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={known}',
               '-o', 'KexAlgorithms=curve25519-sha256', '-o', 'Ciphers=aes256-ctr',
               '-o', 'MACs=hmac-sha2-256', '-o', 'HostKeyAlgorithms=ssh-ed25519',
               'alumno@127.0.0.1', 'whoami; hostname; printf "LAB4_SSH_OK\\n"; date -u']
        with (evidence / '04-cliente-debug.log').open('w') as debug, (evidence / '05-sesion.txt').open('w') as out:
            run(ssh, stdout=out, stderr=debug)
        debug_text = (evidence / '04-cliente-debug.log').read_text()
        for line in ['kex: algorithm: curve25519-sha256', 'kex: host key algorithm: ssh-ed25519',
                     'cipher: aes256-ctr MAC: hmac-sha2-256']:
            if line not in debug_text:
                raise RuntimeError(f'No se acreditó la negociación: {line}')
    finally:
        run(DC + ['exec', '-T', 'ssh', 'sh', '-c', 'kill -INT "$(cat /tmp/lab-capture.pid)"'])
        time.sleep(0.5)
        run(DC + ['cp', 'ssh:/tmp/lab-ssh.pcap', str(evidence / '06-ssh.pcap')])
        (evidence / '09-captura.log').write_text(run(DC + ['exec', '-T', 'ssh', 'cat', '/tmp/lab-capture.log'], capture_output=True).stdout)
        (evidence / '07-servidor.log').write_text(run(DC + ['logs', '--no-color', 'ssh'], capture_output=True).stdout)
    if (evidence / '06-ssh.pcap').stat().st_size <= 24:
        raise RuntimeError('La captura está vacía; revisar 09-captura.log.')
    tshark = shutil.which('tshark')
    if not tshark and Path('/Applications/Wireshark.app/Contents/MacOS/tshark').exists():
        tshark = '/Applications/Wireshark.app/Contents/MacOS/tshark'
    if tshark:
        with (evidence / '08-paquetes.txt').open('w') as out:
            run([tshark, '-r', str(evidence / '06-ssh.pcap'), '-Y', 'tcp.port == 22'], stdout=out)
    print(f'Conexión SSH y algoritmos verificados. Evidencias: {evidence}')
    print('El contenedor sigue disponible en 127.0.0.1:2222. Para detenerlo: docker compose down')


if __name__ == '__main__':
    main()
