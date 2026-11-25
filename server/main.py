import json
import os
import hashlib
import hmac
from dataclasses import dataclass
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Depends, Header, HTTPException, Response
from pydantic import BaseModel
from shared.crypto import RsaService, AesService, AesKey, raw

rsa = RsaService()
aes = AesService()
keys = {}
sessions = {}
SESSION_TTL = int(os.getenv("SESSION_TTL_SECONDS", "60"))
if SESSION_TTL <= 0: raise ValueError("SESSION_TTL_SECONDS must be positive")

@dataclass
class Session:
    key: AesKey
    expired_at: datetime

    @property
    def valid(self):
        return datetime.now(timezone.utc) < self.expired_at

def require_session(x_session_id: str = Header(...)):
    session = sessions.get(x_session_id)
    if session is None: raise HTTPException(404, "Session not found")
    if not session.valid: raise HTTPException(440, "Session expired")
    return session

@asynccontextmanager
async def lifespan(app):
    keys.clear(); sessions.clear()
    for i in range(1, 11): keys[i] = rsa.generate_crypto_keys()
    yield

app = FastAPI(title='Lab 7 - Data integrity', lifespan=lifespan)

class Cipher(BaseModel):
    ciphertext: str

@app.post('/api/crypto-keys/generate/rsa-keys', response_model=int)
async def generate():
    try:
        pair = rsa.generate_crypto_keys()
        i = max(keys, default=0) + 1
        keys[i] = pair
        return i
    except Exception as e:
        raise HTTPException(400, 'RSA generation failed') from e

@app.get('/api/crypto-keys/rsa-public-key/{id}', response_model=str)
async def public_key(id: int):
    if id not in keys: raise HTTPException(404, 'RSA key not found')
    return keys[id].public_key

@app.get('/api/crypto-keys/random', response_model=str)
async def random_key(response: Response):
    i = secrets.choice(list(keys))
    response.headers['x-rsa-id'] = str(i)
    return keys[i].public_key

@app.post('/api/sessions')
async def create_session(body: Cipher, x_rsa_id: int = Header(...)):
    if x_rsa_id not in keys: raise HTTPException(404, 'RSA key not found')
    try:
        data = json.loads(rsa.decrypt(keys[x_rsa_id].private_key, body.ciphertext))
        sid = data['session_id']
        key = AesKey(data['key'], data['iv'])
        if not isinstance(sid, str) or not sid or len(raw(key.key)) != 32 or len(raw(key.iv)) != 12: raise ValueError()
    except Exception as e: raise HTTPException(400, 'Invalid session data') from e
    if sid in sessions: raise HTTPException(409, 'Session already exists')
    sessions[sid] = Session(key, datetime.now(timezone.utc) + timedelta(seconds=SESSION_TTL))
    return {'status': 'created', 'session_id': sid, 'expired_at': sessions[sid].expired_at.isoformat()}

@app.get('/api/sessions')
async def list_sessions():
    return [{'session_id': sid, 'valid': session.valid, 'expired_at': session.expired_at.isoformat()} for sid, session in sessions.items()]

@app.post('/api/messages', response_model=Cipher)
async def message(body: Cipher, x_hash: str = Header(...), session: Session = Depends(require_session)):
    key = session.key
    try: plain = aes.decrypt(key, body.ciphertext)
    except Exception as e: raise HTTPException(400, 'Invalid encrypted message') from e
    expected = hashlib.sha256(plain.encode('utf-8')).hexdigest()
    if not x_hash.isascii() or not hmac.compare_digest(expected, x_hash):
        raise HTTPException(400, 'Hash mismatch: data integrity check failed')
    reply = f'{plain}. Received: {datetime.now(timezone.utc).isoformat()}'
    return Cipher(ciphertext=aes.encrypt(key, reply))
