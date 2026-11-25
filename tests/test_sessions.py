from datetime import datetime, timezone, timedelta
import hashlib
import pytest
from fastapi.testclient import TestClient
from server.main import app, sessions
from client import Client

@pytest.fixture
def pair():
    with TestClient(app) as http:
        yield http, Client(http)

def test_reuse(pair):
    http, client = pair
    assert client.exchange('Привіт').startswith('Привіт')
    sid = client.sid
    client.exchange('Second')
    assert client.sid == sid
    assert len(http.get('/api/sessions').json()) == 1

def test_expiration_and_retry(pair):
    http, client = pair
    client.exchange('First')
    old = client.sid
    sessions[old].expired_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    r = http.post('/api/messages', json={'ciphertext': client.aes.encrypt(client.key, 'Again')}, headers={'x-session-id': old, 'x-hash': hashlib.sha256(b'Again').hexdigest()})
    assert r.status_code == 440
    assert client.exchange('Again').startswith('Again')
    assert client.sid != old
    rows = {r['session_id']:r for r in http.get('/api/sessions').json()}
    assert rows[old]['valid'] is False
    assert rows[client.sid]['valid'] is True
    assert datetime.fromisoformat(rows[old]['expired_at']).utcoffset() == timedelta(0)
    assert set(rows[old]) == {'session_id','valid','expired_at'}

def test_wrong_hash(pair):
    http, client = pair
    client.create_session()
    r = http.post('/api/messages', json={'ciphertext':client.aes.encrypt(client.key,'Hello')}, headers={'x-session-id':client.sid,'x-hash':'0'*64})
    assert r.status_code == 400
    assert 'Hash mismatch' in r.json()['detail']
