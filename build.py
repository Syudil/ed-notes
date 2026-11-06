"""Build the password-protected index.html for GitHub Pages.

The app (../E&D.html) is encrypted with AES-256-GCM using a key derived from the site
password (PBKDF2-SHA256). Only the encrypted copy is published; without the password
the published page contains no readable app.

Usage (from this folder):
    .venv/bin/python build.py                 # uses the password in site-password.txt
    .venv/bin/python build.py "new password"  # sets a new password and saves it there

Changing the password: everyone needs the new one, and "remembered" logins stop working.
"""
import base64
import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, '..', 'E&D.html')
TEMPLATE = os.path.join(HERE, 'gate-template.html')
OUT = os.path.join(HERE, 'index.html')
PW_FILE = os.path.join(HERE, 'site-password.txt')
SALT_FILE = os.path.join(HERE, 'gate-salt.txt')  # kept between builds so remembered logins survive app updates
ITERATIONS = 600_000


def main():
    new_pw = len(sys.argv) > 1
    if new_pw:
        password = sys.argv[1].strip()
        with open(PW_FILE, 'w') as f:
            f.write(password + '\n')
    else:
        with open(PW_FILE) as f:
            password = f.read().strip()
    if len(password) < 8:
        sys.exit('Password must be at least 8 characters.')

    with open(SOURCE, 'rb') as f:
        app = f.read()

    if new_pw or not os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'w') as f:
            f.write(base64.b64encode(os.urandom(16)).decode('ascii'))
    with open(SALT_FILE) as f:
        salt = base64.b64decode(f.read().strip())
    iv = os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(password.encode('utf-8'))
    ct = AESGCM(key).encrypt(iv, app, None)

    b64 = lambda b: base64.b64encode(b).decode('ascii')
    payload = json.dumps({'salt': b64(salt), 'iv': b64(iv), 'it': ITERATIONS, 'ct': b64(ct)})

    with open(TEMPLATE, encoding='utf-8') as f:
        page = f.read()
    assert page.count('/*PAYLOAD*/null') == 1
    page = page.replace('/*PAYLOAD*/null', payload)
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(page)
    print(f'Built index.html ({len(page) // 1024} KB) from {os.path.basename(SOURCE)}')


if __name__ == '__main__':
    main()
