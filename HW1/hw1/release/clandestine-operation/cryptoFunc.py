from Crypto.Cipher import AES
from myErrors import *
import binascii
import secret

def pad(m):
    length = 16-len(m) % 16
    return m+chr(length).encode()*length


def unpad(c):
    length = c[-1]
    for char in c[-length:]:
        if char != length:
            raise paddingError('incorrect padding')
    return c[:-length]


def encrypt(m):
    aes = AES.new(secret.key, AES.MODE_CBC, secret.iv)
    return binascii.hexlify(aes.encrypt(pad(m))).decode()


def decrypt(c):
    aes = AES.new(secret.key, AES.MODE_CBC, secret.iv)
    return unpad(aes.decrypt(binascii.unhexlify(c))).decode()