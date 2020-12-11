import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import *


def encrypt(key: bytes, iv: bytes, message: str) -> str:
    block_size = 16
    data = message.encode()

    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(pad(data, block_size))
    ciphertext = base64.b64encode(ciphertext).decode("utf-8")

    return ciphertext


def decrypt(key: bytes, iv: bytes, encrypted_message: str) -> str:
    block_size = 16
    data = base64.b64decode(encrypted_message)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(data), block_size).decode()

    return plaintext