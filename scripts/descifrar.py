#!/usr/bin/env python3
"""Descifra el formato observado en transacciones_cifradas.pcap.

Un registro completo por payload TCP/UDP (como en la captura del docente):
RSA_PIN| + salt[16] + RSA-OAEP-SHA256[k/8]
AESGCM|  + nonce[12] + ciphertext[n] + tag[16]
No es un reensamblador TCP de propósito general. No divide bytes binarios por '|'.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from scapy.all import IP, IPv6, TCP, UDP, PcapReader

RSA_PREFIX = b'RSA_PIN|'
AES_PREFIX = b'AESGCM|'


def derive_key(pin, salt):
    if not re.fullmatch(rb'[0-9]{4}', pin):
        raise ValueError('El PIN recuperado no contiene exactamente cuatro dígitos ASCII.')
    if len(salt) != 16:
        raise ValueError('La salt debe medir 16 bytes.')
    # Mantener el PIN como bytes: convertir 0042 a int perdería los ceros.
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(pin)


def recover_pin(payload, private_key):
    size = (private_key.key_size + 7) // 8
    if not payload.startswith(RSA_PREFIX) or len(payload) != len(RSA_PREFIX) + 16 + size:
        raise ValueError('Registro RSA incompleto o longitud incompatible con la clave.')
    salt = payload[8:24]
    encrypted_pin = payload[24:]
    try:
        pin = private_key.decrypt(encrypted_pin, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    except ValueError as exc:
        raise ValueError('RSA-OAEP falló: clave incorrecta, registro alterado o parámetros distintos.') from exc
    return pin, salt, encrypted_pin


def decrypt_transaction(payload, key):
    if not payload.startswith(AES_PREFIX) or len(payload) < 7 + 12 + 16:
        raise ValueError('Registro AESGCM incompleto.')
    nonce = payload[7:19]
    encrypted_and_tag = payload[19:]
    try:
        # cryptography verifica el tag antes de devolver el mensaje; sin AAD en esta captura.
        plaintext = AESGCM(key).decrypt(nonce, encrypted_and_tag, None)
    except InvalidTag as exc:
        raise ValueError('AUTENTICIDAD FALLIDA: tag, ciphertext, clave, nonce o AAD incorrectos.') from exc
    return plaintext, nonce, encrypted_and_tag[-16:]


def read_records(path):
    records = []
    seen = {}
    with PcapReader(str(path)) as packets:
        for frame, packet in enumerate(packets, 1):
            transport = packet.getlayer(TCP) or packet.getlayer(UDP)
            network = packet.getlayer(IP) or packet.getlayer(IPv6)
            if transport is None or network is None:
                continue
            payload = bytes(transport.payload)
            if not payload:
                continue
            flow = (network.src, int(transport.sport), network.dst, int(transport.dport))
            if isinstance(transport, TCP):
                identity = (*flow, int(transport.seq), len(payload))
                if identity in seen:
                    if seen[identity] != payload:
                        raise ValueError(f'Trama {frame}: retransmisión TCP con bytes distintos.')
                    continue
                seen[identity] = payload
            kind = ('RSA_PIN' if payload.startswith(RSA_PREFIX) else
                    'AESGCM' if payload.startswith(AES_PREFIX) else None)
            records.append({'trama': frame, 'tipo': kind, 'flujo': flow, 'payload': payload,
                            'protocolo': 'TCP' if isinstance(transport, TCP) else 'UDP'})
    return records


def parse_transaction(plaintext):
    text = plaintext.decode('utf-8')
    fields = dict(item.split('=', 1) for item in text.split('|')[1:] if '=' in item)
    if not all(k in fields for k in ('ID', 'DE', 'A', 'MONTO')):
        raise ValueError('El mensaje autenticado no tiene los campos ID, DE, A y MONTO esperados.')
    return {'id': fields['ID'], 'remitente': fields['DE'], 'destinatario': fields['A'],
            'monto': fields['MONTO'], 'original': text}


def analyze(pcap, private_path, public_path=None):
    private = serialization.load_pem_private_key(Path(private_path).read_bytes(), password=None)
    if not isinstance(private, rsa.RSAPrivateKey):
        raise ValueError('La clave privada no es RSA.')
    if public_path:
        public = serialization.load_pem_public_key(Path(public_path).read_bytes())
        if not isinstance(public, rsa.RSAPublicKey) or public.public_numbers() != private.public_key().public_numbers():
            raise ValueError('Las claves pública y privada no corresponden al mismo par RSA.')
    records = read_records(pcap)
    rsa_records = [r for r in records if r['tipo'] == 'RSA_PIN']
    if len(rsa_records) != 1:
        raise ValueError(f'Se esperaba un registro RSA_PIN completo; se encontraron {len(rsa_records)}.')
    first = rsa_records[0]
    # Rechazar segmentos sin marcador en el flujo analizado: evita omitir fragmentos silenciosamente.
    if any(r['flujo'] == first['flujo'] and r['tipo'] is None for r in records):
        raise ValueError('Payload sin marcador en el flujo: se requiere reensamblado TCP o revisar el formato.')
    pin, salt, encrypted_pin = recover_pin(first['payload'], private)
    key = derive_key(pin, salt)
    aes_records = [r for r in records if r['tipo'] == 'AESGCM']
    if not aes_records:
        raise ValueError('No se encontraron transacciones AESGCM completas.')
    transactions, nonces = [], set()
    for record in aes_records:
        if record['flujo'] != first['flujo']:
            raise ValueError('Se detectaron varios flujos; separar sus sesiones y claves antes de descifrar.')
        try:
            plaintext, nonce, tag = decrypt_transaction(record['payload'], key)
            transaction = parse_transaction(plaintext)
        except (ValueError, UnicodeError) as exc:
            raise ValueError(f'Trama {record["trama"]}: {exc}') from exc
        if nonce in nonces:
            raise ValueError(f'Trama {record["trama"]}: nonce repetido con la misma clave AES.')
        nonces.add(nonce)
        transactions.append({'trama': record['trama'], **transaction,
                             'nonce_hex': nonce.hex(), 'tag_hex': tag.hex(),
                             'autenticidad': 'VERIFICADA', 'payload_bytes': len(record['payload'])})
    return {'archivo': Path(pcap).name, 'sha256_pcap': hashlib.sha256(Path(pcap).read_bytes()).hexdigest(),
            'rsa_bits': private.key_size, 'trama_rsa': first['trama'], 'flujo': first['flujo'],
            'pin': pin.decode('ascii'), 'salt_hex': salt.hex(), 'pin_cifrado_hex': encrypted_pin.hex(),
            'scrypt': {'n': 2**14, 'r': 8, 'p': 1, 'length': 32},
            'clave_aes_hex': key.hex(), 'aad': None, 'transacciones': transactions}


def save_results(result, output):
    output.mkdir(parents=True, exist_ok=True)
    (output / 'resultado.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    fields = ['trama', 'id', 'remitente', 'destinatario', 'monto', 'autenticidad']
    with (output / 'transacciones.csv').open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(result['transacciones'])
    lines = [f"PIN recuperado mediante RSA-OAEP-SHA256: {result['pin']}",
             f"Trama RSA_PIN: {result['trama_rsa']}", f"Salt (16 bytes): {result['salt_hex']}",
             f"Clave AES (32 bytes): {result['clave_aes_hex']}",
             'Scrypt: n=16384, r=8, p=1',
             f"Transacciones autenticadas: {len(result['transacciones'])}", '']
    for t in result['transacciones']:
        lines += [f"[Trama {t['trama']}] Autenticidad: {t['autenticidad']}", t['original'], '']
    text = '\n'.join(lines)
    (output / 'transacciones.txt').write_text(text, encoding='utf-8')
    # Estos archivos contienen secretos del ejercicio y se excluyen de Git.
    (output / 'salt.bin').write_bytes(bytes.fromhex(result['salt_hex']))
    (output / 'pin_cifrado.bin').write_bytes(bytes.fromhex(result['pin_cifrado_hex']))
    print(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', type=Path, default=Path('datos/transacciones_cifradas.pcap'))
    parser.add_argument('--private-key', type=Path, default=Path('datos/clave_privada.pem'))
    parser.add_argument('--public-key', type=Path, default=Path('datos/clave_publica.pem'))
    parser.add_argument('--output', type=Path, default=Path('resultados'))
    args = parser.parse_args()
    try:
        result = analyze(args.pcap, args.private_key, args.public_key)
        save_results(result, args.output)
    except (ValueError, OSError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
