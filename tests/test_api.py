import json
import hashlib
from fastapi.testclient import TestClient
from server.main import app
from shared.crypto import RsaService, AesService

def test_api():
    with TestClient(app) as c:
        i = c.post('/api/crypto-keys/generate/rsa-keys').json()
        assert i == 11
        assert c.get('/api/crypto-keys/rsa-public-key/999').status_code == 404
        assert c.get(f'/api/crypto-keys/rsa-public-key/{i}').status_code == 200
        r = c.get('/api/crypto-keys/random'); a = AesService(); k = a.generate_secret_key()
        payload = json.dumps({'session_id':'test','key':k.key,'iv':k.iv})
        cipher = RsaService().encrypt(r.json(), payload)
        assert c.post('/api/sessions',json={'ciphertext':cipher},headers={'x-rsa-id':r.headers['x-rsa-id']}).status_code == 200
        result = c.post('/api/messages',json={'ciphertext':a.encrypt(k,'Hello')},headers={'x-session-id':'test','x-hash':hashlib.sha256(b'Hello').hexdigest()})
        assert result.status_code == 200
        assert a.decrypt(k,result.json()['ciphertext']).startswith('Hello. Received:')
        assert c.post('/api/messages',json={'ciphertext':'bad'},headers={'x-session-id':'missing','x-hash':'0'*64}).status_code == 404
