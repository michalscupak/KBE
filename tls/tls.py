import math
import os
import random
import hashlib
import base64
import string

from Crypto.Cipher import AES
from Crypto.Util.Padding import *
from Crypto.Util.number import isPrime

# region Task 1
# agreed public parameters
# p = 37
# g = 5

p = int(
    "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16)
g = 2

# Alice chooses secret and sends A to Bob
a = random.randint(2, p - 1)
A = pow(g, a, p)  # modular exponentiation

# Bob chooses secret and sends B to Alice
b = random.randint(2, p - 1)
B = pow(g, b, p)  # modular exponentiation

# Then each compute the secret (symmetric)
s = pow(B, a, p)  # Alice
s = pow(A, b, p)  # Bob
# endregion

# region Task 2
hash = hashlib.sha1(str(s).encode())
key = hash.digest()[:-4]  # size 16 bytes
print(key)


# endregion

# region Task 3
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


# test script bulk_cipher.py
BLOCK_SIZE = 16

key = os.urandom(BLOCK_SIZE)
iv = os.urandom(BLOCK_SIZE)
msg = ''.join(random.choice(string.ascii_lowercase) for i in range(1024))
assert decrypt(key, iv, encrypt(key, iv, msg)) == msg


# endregion

# region Task 4
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
        self.A = pow(g, a, p)
        return self.A

    def receive_public_key(self, B):
        self.B = B

    def send_message(self):
        iv = os.urandom(16)
        self.iv = iv
        self.s = pow(B, a, p)
        h = hashlib.sha1(str(self.s).encode())
        self.key = h.digest()[:-4]
        ct = encrypt(self.key, self.iv, self.msg)
        ct = bytes(ct, 'utf-8')
        ct = iv + ct
        return ct

    def receive_message(self, ct):
        self.s = pow(B, a, p)
        h = hashlib.sha1(str(self.s).encode())
        self.key = h.digest()[:-4]
        iv = ct[0:16]
        ct = str(ct[16:], 'utf-8')
        msg = decrypt(self.key, iv, ct)
        self.msg = msg


# test script tls_101.py
alice = Agent("I'M 5UppER Kewl h4zKEr")
bob = Agent()

# Alice has da message, Bob doesn't
assert alice.msg
assert not bob.msg

# Negotiate parameters publicly
bob.receive_public_data(*alice.send_public_data())
alice.receive_public_data(*bob.send_public_data())

# Exchange keys publicly
bob.receive_public_key(alice.send_public_key())
alice.receive_public_key(bob.send_public_key())

# Pass da message
bob.receive_message(alice.send_message())
# Bob has it now
assert alice.msg == bob.msg


# endregion

# region Task 5
class MITM:
    def __init__(self):
        self.p = 0
        self.g = 0
        self.a = 0
        self.A = 0
        self.B = 0
        self.msg = ""
        self.s = 0
        self.key = 0

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
        self.A = pow(g, a, p)
        return self.A

    def receive_public_key(self, B):
        self.B = B

    def intercept_message(self, input):
        self.s = pow(B, a, p)
        h = hashlib.sha1(str(self.s).encode())
        self.key = h.digest()[:-4]
        iv = input[0:16]
        ct = str(input[16:], 'utf-8')
        msg = decrypt(self.key, iv, ct)
        self.msg = msg
        return input


# test script itls_101.py
alice = Agent("I'M 5UppER Kewl h4zKEr")
bob = Agent()
mallory = MITM()

# Alice has da message, Bob doesn't
assert alice.msg
assert not bob.msg

# Negotiate parameters publicly
mallory.receive_public_data(*alice.send_public_data())
bob.receive_public_data(*mallory.send_public_data())
mallory.receive_public_data(*bob.send_public_data())
alice.receive_public_data(*mallory.send_public_data())

# Exchange keys publicly
mallory.receive_public_key(alice.send_public_key())
bob.receive_public_key(mallory.send_public_key())
mallory.receive_public_key(bob.send_public_key())
alice.receive_public_key(mallory.send_public_key())

# Pass da message
bob.receive_message(mallory.intercept_message(alice.send_message()))
# Bob has it now
assert bob.msg == alice.msg
# Mallory too
assert mallory.msg == alice.msg
# endregion

# region Task 6
# suggested values
p = 13604067676942311473880378997445560402287533018336255431768131877166265134668090936142489291434933287603794968158158703560092550835351613469384724860663783
q = 20711176938531842977036011179660439609300527493811127966259264079533873844612186164429520631818559067891139294434808806132282696875534951083307822997248459
e = 3


def extended_euclidean(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_euclidean(b % a, a)
        return gcd, y - (b // a) * x, x


def invmod(a: int, b: int) -> int:
    # (x * a) % b = 1
    if math.gcd(a, b) != 1:
        print("Inverse does not exist!")
    else:
        g, x, _ = extended_euclidean(a, b)
        return x % b


assert invmod(19, 1212393831) == 701912218
invmod(13, 91)


def encrypt_int(m, pub_key, n):
    return pow(m, pub_key, n)


def decrypt_int(m, priv_key, n):
    return pow(m, priv_key, n)


def encrypt(m, pub_key, n):
    m = int.from_bytes(m, 'big')
    pub_key = int.from_bytes(pub_key, 'big')
    n = int.from_bytes(n, 'big')
    ct = encrypt_int(m, pub_key, n)
    return ct.to_bytes((ct.bit_length() + 7) // 8, byteorder='big')


def decrypt(m, priv_key, n):
    m = int.from_bytes(m, 'big')
    priv_key = int.from_bytes(priv_key, 'big')
    n = int.from_bytes(n, 'big')
    pt = decrypt_int(m, priv_key, n)
    return pt.to_bytes((pt.bit_length() + 7) // 8, byteorder='big')


# RSA key generation
n = p * q  # modulus
if isPrime(p) and isPrime(q):
    fi_n = (p - 1) * (q - 1)  # kept secret

    if math.gcd(e, fi_n) == 1:
        d = invmod(e, fi_n)  # secret private key exponent

public = (n, e)
private = (n, d)

# RSA int encryption/decryption test
m = int.from_bytes(os.urandom(16), 'big')
assert m == decrypt_int(encrypt_int(m, e, n), d, n)

# RSA bytes encryption/decryption test
m = os.urandom(16)
e = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')
d = d.to_bytes((d.bit_length() + 7) // 8, byteorder='big')
n = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
assert m == decrypt(encrypt(m, e, n), d, n)
# endregion
