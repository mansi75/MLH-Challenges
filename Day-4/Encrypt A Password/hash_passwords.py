import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt():
    password_provided = 'password'
    password = password_provided.encode()

    salt = b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05"

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=default_backend())

    key = base64.urlsafe_b64encode(kdf.derive(password))

    with open('key.key', 'wb') as f:
        f.write(key)


    with open('passwords.txt', 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    with open('passwords.txt.encrypted', 'wb') as f:
        f.write(encrypted)
    os.remove('passwords.txt')


def decrypt():
    file = open('key.key', 'rb')
    key = file.read()
    file.close()

    with open('passwords.txt.encrypted', 'rb') as f:
        data = f.read()

    fernet = Fernet(key)
    encrypted = fernet.decrypt(data)

    # Open the decrypted file
    with open('passwords.txt', 'wb') as f:
        f.write(encrypted)
