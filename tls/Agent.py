import hashlib
import os

from Crypto.Random import random
from Crypto.Util.number import isPrime
from tls import cipher


class Agent:
    def __init__(self, message=()):
        self.msg = message
        self.p = 0
        self.g = 0
        self.a = 0
        self.A = 0
        self.B = 0
        self.s = 0
        self.key = 0
        self.iv = 0

    def send_public_data(self):
        if self.p == 0 or self.g == 0:
            p = random.getrandbits(2048)
            g = random.getrandbits(2048)

            while not (isPrime(p)):
                p = random.getrandbits(2048)

            while not (isPrime(p)):
                g = random.getrandbits(2048)

            self.p = p
            self.g = g
        return self.p, self.g

    def receive_public_data(self, p, g):
        self.p = p
        self.g = g

    def send_public_key(self):
        self.a = random.randint(2, self.p - 1)
        self.A = pow(self.g, self.a, self.p)
        return self.A

    def receive_public_key(self, B):
        self.B = B

    def send_message(self):
        iv = os.urandom(16)
        self.iv = iv
        self.s = pow(self.B, self.a, self.p)
        h = hashlib.sha1(str(self.s).encode())
        self.key = h.digest()[:-4]
        ct = cipher.encrypt(self.key, self.iv, self.msg)
        ct = bytes(ct, 'utf-8')
        ct = iv + ct
        return ct

    def receive_message(self, ct):
        self.s = pow(self.B, self.a, self.p)
        h = hashlib.sha1(str(self.s).encode())
        self.key = h.digest()[:-4]
        iv = ct[0:16]
        ct = str(ct[16:], 'utf-8')
        msg = cipher.decrypt(self.key, iv, ct)
        self.msg = msg