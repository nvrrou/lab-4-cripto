"""Pruebas de recuperación y rechazo de datos alterados, sin datos privados externos."""
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scapy.all import IP, TCP, Raw, wrpcap

from scripts.descifrar import analyze, derive_key, recover_pin, decrypt_transaction


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.salt = bytes(range(16))
        cls.pin = b'0042'
        cls.key = derive_key(cls.pin, cls.salt)
        cls.rsa_payload = b'RSA_PIN|' + cls.salt + cls.private.public_key().encrypt(
            cls.pin, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        # El nonce incluye '|' para detectar parsers que separan incorrectamente el binario.
        cls.nonce = b'|01234567890'
        cls.message = b'TRANSACCION COMPLETADA|ID=TRX-001|DE=Ana|A=Luis|MONTO=123'
        cls.aes_payload = b'AESGCM|' + cls.nonce + AESGCM(cls.key).encrypt(cls.nonce, cls.message, None)

    def test_rsa_preserves_leading_zeros(self):
        pin, salt, encrypted = recover_pin(self.rsa_payload, self.private)
        self.assertEqual((pin, salt, len(encrypted)), (b'0042', self.salt, 256))

    def test_aes_authentication_and_binary_delimiter(self):
        self.assertEqual(decrypt_transaction(self.aes_payload, self.key)[0], self.message)

    def test_rejects_changed_nonce_ciphertext_and_tag(self):
        for offset in [7, 19, len(self.aes_payload) - 1]:
            with self.subTest(offset=offset):
                altered = bytearray(self.aes_payload)
                altered[offset] ^= 1
                with self.assertRaisesRegex(ValueError, 'AUTENTICIDAD FALLIDA'):
                    decrypt_transaction(bytes(altered), self.key)

    def test_rejects_wrong_aes_key(self):
        with self.assertRaisesRegex(ValueError, 'AUTENTICIDAD FALLIDA'):
            decrypt_transaction(self.aes_payload, derive_key(b'0043', self.salt))

    def test_rejects_wrong_rsa_key(self):
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaisesRegex(ValueError, 'RSA-OAEP falló'):
            recover_pin(self.rsa_payload, wrong)

    def test_rejects_truncated_records(self):
        with self.assertRaises(ValueError):
            recover_pin(self.rsa_payload[:-1], self.private)
        with self.assertRaises(ValueError):
            decrypt_transaction(self.aes_payload[:20], self.key)

    def test_pcap_end_to_end_and_retransmission(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            private = directory / 'private.pem'
            private.write_bytes(self.private.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            packets = [IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=1234, dport=4444, seq=1) / Raw(self.rsa_payload),
                       IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=1234, dport=4444, seq=281) / Raw(self.aes_payload)]
            pcap = directory / 'test.pcap'
            wrpcap(str(pcap), packets + [packets[1]])
            result = analyze(pcap, private)
            self.assertEqual(result['pin'], '0042')
            self.assertEqual(len(result['transacciones']), 1)
            self.assertEqual(result['transacciones'][0]['original'], self.message.decode())
            # Un segmento adicional sin marcador no puede descartarse silenciosamente.
            packets.append(IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=1234, dport=4444, seq=999) / Raw(b'fragmento'))
            wrpcap(str(pcap), packets)
            with self.assertRaisesRegex(ValueError, 'reensamblado'):
                analyze(pcap, private)


if __name__ == '__main__':
    unittest.main()
