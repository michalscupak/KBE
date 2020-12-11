import hashlib
import os

from Crypto.Random import random
from tls import cipher


class MITM:
    def __init__(self):
        self.p = 0
        self.g = 0
        self.a = 0
        self.A_1 = 0
        self.A_2 = 0
        self.B_1 = 0
        self.B_2 = 0
        self.msg = ""
        self.s = 0
        self.key = 0

    def send_public_data(self):
        return self.p, self.g

    def receive_public_data(self, p, g):
        self.p = p
        self.g = g

    def send_public_key(self):
        if self.a == 0:
            self.a = random.randint(2, self.p - 1)
        if self.A_2 != 0:
            self.A_1 = pow(self.g, self.a, self.p)
            return self.A_1
        else:
            self.A_2 = pow(self.g, self.a, self.p)
            return self.A_2

    def receive_public_key(self, B):
        if self.B_1 != 0:
            self.B_2 = B;
        else:
            self.B_1 = B

    def intercept_message(self, ct):
        self.s = pow(self.B_1, self.a, self.p)
        h = hashlib.sha1(str(self.s).encode())
        self.key = h.digest()[:-4]
        iv = ct[0:16]
        ct = str(ct[16:], 'utf-8')
        msg = cipher.decrypt(self.key, iv, ct)
        self.msg = msg

        iv = os.urandom(16)
        self.iv = iv
        self.s = pow(self.B_2, self.a, self.p)
        h = hashlib.sha1(str(self.s).encode())
        self.key = h.digest()[:-4]
        ct = cipher.encrypt(self.key, self.iv, self.msg)
        ct = bytes(ct, 'utf-8')
        ct = iv + ct
        return ct