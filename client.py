import json
import uuid
import os
import hashlib
import requests
from shared.crypto import RsaService, AesService

URL = os.getenv('API_URL', 'http://127.0.0.1:8000')

class Client:
    def __init__(self, http=requests):
        self.http = http
        self.rsa, self.aes = RsaService(), AesService()
        self.sid = None

    def create_session(self):
        r = self.http.get(URL + '/api/crypto-keys/random', timeout=10)
        r.raise_for_status()
        key = self.aes.generate_secret_key()
        sid = uuid.uuid4().hex
        payload = json.dumps({'session_id': sid, 'key': key.key, 'iv': key.iv}, separators=(',', ':'))
        cipher = self.rsa.encrypt(r.json(), payload)
        result = self.http.post(URL + '/api/sessions', json={'ciphertext': cipher}, headers={'x-rsa-id': r.headers['x-rsa-id']}, timeout=10)
        result.raise_for_status()
        self.sid, self.key = sid, key
        print('New session:', sid, '\nExpires (UTC):', result.json()['expired_at'])

    def exchange(self, message, bad_hash=False):
        if self.sid is None:
            self.create_session()
        digest = hashlib.sha256(message.encode('utf-8')).hexdigest()
        if bad_hash:
            digest = '0' * 64
        for attempt in range(2):
            cipher = self.aes.encrypt(self.key, message)
            print('Session ID:', self.sid, '\nSHA-256:', digest, '\nEncrypted request:', cipher)
            r = self.http.post(URL + '/api/messages', json={'ciphertext': cipher}, headers={'x-session-id': self.sid, 'x-hash': digest}, timeout=10)
            print('HTTP status:', r.status_code)
            if r.status_code == 440 and attempt == 0:
                print('Session expired (440). Creating a new session and retrying.')
                self.create_session()
                continue
            if r.status_code != 200:
                print('Server response:', r.text)
                r.raise_for_status()
            reply = self.aes.decrypt(self.key, r.json()['ciphertext'])
            print('Integrity check: OK\nEncrypted response:', r.json()['ciphertext'], '\nDecrypted response:', reply)
            return reply

if __name__ == '__main__':
    client = Client()
    while True:
        try:
            message = input('Enter message (exit to quit, /bad to test hash): ')
            if message.lower() == 'exit': break
            client.exchange('Integrity test' if message == '/bad' else message, bad_hash=message == '/bad')
        except (EOFError, KeyboardInterrupt): break
        except requests.RequestException as e: print('HTTP error:', e)
