import pytest
from shared.crypto import RsaService, AesService
from cryptography.exceptions import InvalidTag

def test_rsa():
    s = RsaService(); k = s.generate_crypto_keys()
    assert s.decrypt(k.private_key, s.encrypt(k.public_key, 'Привіт')) == 'Привіт'

def test_aes():
    s = AesService(); k = s.generate_secret_key()
    c = s.encrypt(k, 'Привіт')
    assert s.decrypt(k, c) == 'Привіт'
    assert c != s.encrypt(k, 'Привіт')

def test_wrong_key():
    s = AesService()
    with pytest.raises(InvalidTag): s.decrypt(s.generate_secret_key(), s.encrypt(s.generate_secret_key(), 'test'))
