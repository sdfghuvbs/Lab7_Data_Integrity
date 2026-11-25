# Laboratory 7 — Data integrity
Python 3.12 recommended. Run from project root.

    python -m pip install -r requirements.txt
    python -m pytest -v
    python -m uvicorn server.main:app --port 8000

In another terminal: `python client.py`. Send two messages within 60 seconds, wait 65 seconds, send another message, then enter `/bad` to test an invalid hash. Enter `exit` to quit. Swagger: http://127.0.0.1:8000/docs — GET /api/sessions lists valid and expired sessions. TTL is configured via SESSION_TTL_SECONDS (default 60). Sessions are in memory and disappear on restart.

Docker: `docker build -t lab7 .` then `docker run --rm -p 8000:8000 --name lab7-server lab7` after stopping local Uvicorn.

SHA-256 is an unkeyed hash, not a digital signature. AES-GCM authenticates encrypted messages; the additional hash comparison implements the lab requirement. This educational protocol does not replace TLS or authenticate the server's RSA public key.
