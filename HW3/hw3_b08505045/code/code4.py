from pwn import *
from Crypto.Util.number import getPrime, isPrime, GCD, bytes_to_long, long_to_bytes
from random import randrange
from hashlib import sha256

def HashToPrime(content):
        '''
        Hash a content to Prime domain.
        The content must be encoded in bytes.
        '''
        def PrimeTest(p):
            return isPrime(p) and p > 2
        
        def H(_y):
            return bytes_to_long(sha256(_y).digest())
        
        y = H(content)
        while not PrimeTest(y):
            y = H(long_to_bytes(y))

        return y

def xgcd(a, b):
    """return (x, y) such that a*x + b*y = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return x0, y0

r = remote('cns.csie.org', 4001)
r.recvuntil(b'N = ')
N = int(r.recvline().strip().decode(), 16)
r.recvuntil(b'g = ')
g = int(r.recvline().strip().decode(), 16)
r.recvuntil(b'd = ')
d = int(r.recvline().strip().decode(), 16)

P = 0xfe7fa2d93be7396c7172a7186f4e561949f53e436a7ed65da22786637b7e76081f65b972be84ea612787a07878c1bf9454edf81059f84158efe34b4207f96d71
Q = 0xb76082ea921f3d4729e59d765ff014ad745b6421f1bacc359417e0c2a1aaa318bd96ba0f6476e09bd1db72fa4dfc7fa5aa0ee1bef7bc4f268fb42673e539d3b1
phi = (P - 1) * (Q - 1)

# print(f'N = {N}')
# print(f'g = {g}')
# print(f'd = {d}')
# print(f'P = {P}')
# print(f'Q = {Q}')

# fake membership proof
member3 = 'Member3'
m = HashToPrime(member3.encode())
# forge proof : p^m = d, d = g^(product of all members)
m_inv = pow(m, -1, phi)
p = pow(d, m_inv, N)

r.sendlineafter('[0,1,2] '.encode(), '0'.encode())
r.sendlineafter('message: '.encode(), member3.encode())
r.sendlineafter('message: '.encode(), f'{p}'.encode())
r.recvuntil('flag. '.encode())

flag1 = r.recvline().strip().decode()
print(f'flag1 : {flag1}')

# fake non-membership proof
product = (HashToPrime('Member0'.encode()) * HashToPrime('Member1'.encode()) * HashToPrime('Member2'.encode())) % N
member = 'Member0'
non_m = HashToPrime(member.encode())
a = pow(non_m, -1, phi)

r.sendlineafter(b'[0,1,2] ', b'1')
r.sendlineafter(b'message: ', member.encode())
r.sendlineafter(b'g^a = ', f'{pow(g, a, N)}'.encode())
r.sendlineafter(b'b = ', f'0'.encode())
r.recvuntil(b'flag. ')

flag2 = r.recvline().strip().decode()
print(f'flag2 : {flag2}')