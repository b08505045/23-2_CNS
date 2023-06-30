# Elgmal with reused ephemeral key

from pwn import *
from Crypto.Util.number import getPrime, isPrime, bytes_to_long, long_to_bytes
from random import randint
import base64
import binascii
import math

P = 229427426007004641058038399605893431891338652544880488643534649263550827812892013492489412406570250351976852154191427816707204012255764549959937503449437748973977415513106105897497757095728051081468939079966553921958218909428521019515171147734090784426719929697847543345936614548176336768375245642108499733879

r = remote('cns.csie.org', 6001)
r.recvuntil('P = '.encode())
pk = r.recvuntil('\n'.encode())[:-1]            # public key
r.recvuntil('g = '.encode())
g = r.recvuntil('\n'.encode())[:-1]             # generator
r.recvuntil('= ('.encode())
c1_1 = r.recvuntil(', '.encode())[:-2]          # c1
c1_2 = r.recvuntil(')'.encode())[:-1]           # c2

m2 = b'message'                                 # m2, chosen by attacker
r.sendlineafter('): '.encode(), 'y'.encode())
r.sendlineafter('e: '.encode(), m2)
r.recvuntil('t ('.encode())
c2_1 = r.recvuntil(', '.encode())[:-2]          # c1'
c2_2 = r.recvuntil(')'.encode())[:-1]           # c2'


int_c2_2 = int(c2_2.decode())
long_m2 = bytes_to_long(m2)                     # 30792318992869221

invert_c2_2 = pow(int_c2_2, -1, P)
invert_yk = invert_c2_2 * long_m2 % P           # invert_yk : pk^(-k), k is ephemeral key
int_c1_2 = int(c1_2.decode())
long_m1 = int_c1_2 * invert_yk % P
m1 = long_to_bytes(long_m1)                     # m1
print(m1.decode())