import base64
import os
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64(data): return base64.b64encode(data).decode('ascii')
def raw(data): return base64.b64decode(data, validate=True)

@dataclass
class RsaKeys:
    public_key: str
    private_key: str

class RsaService:
    @staticmethod
    def generate_crypto_keys():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return RsaKeys(b64(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)), b64(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())))
    @staticmethod
    def _padding():
        return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    def encrypt(self, public_key, plain_text):
        key = serialization.load_der_public_key(raw(public_key))
        return b64(key.encrypt(plain_text.encode(), self._padding()))
    def decrypt(self, private_key, cipher_text):
        key = serialization.load_der_private_key(raw(private_key), password=None)
        return key.decrypt(raw(cipher_text), self._padding()).decode()

@dataclass
class AesKey:
    key: str
    iv: str

class AesService:
    def generate_secret_key(self):
        return AesKey(b64(AESGCM.generate_key(bit_length=256)), b64(os.urandom(12)))
    def encrypt(self, aes_key, plain_text):
        nonce = os.urandom(12)
        effective_iv = bytes(a ^ b for a, b in zip(nonce, raw(aes_key.iv)))
        return b64(nonce + AESGCM(raw(aes_key.key)).encrypt(effective_iv, plain_text.encode(), None))
    def decrypt(self, aes_key, cipher_text):
        data = raw(cipher_text)
        effective_iv = bytes(a ^ b for a, b in zip(data[:12], raw(aes_key.iv)))
        return AESGCM(raw(aes_key.key)).decrypt(effective_iv, data[12:], None).decode()
