#! /usr/bin/env python3
from public import pk1, pk2
from secret import flag2, flag3, secret_seed
import hashlib
from binascii import unhexlify
from Crypto.Util.number import bytes_to_long
import signal

def alarm(second):
    def handler(signum, frame):
        print('Timeout!')
        exit()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(second)

class linear_congruential_generator:
    def __init__(self, p):
        self.state = secret_seed
        self.a = 0x9b78f3e598a4eefdb785ad571a91017b85418cd79347515da91d5b95fe99886eab96937f681d52315ca3042240371ed438db3f33150439d71e7fb07f9772a2bd
        self.c = 0xe97d1423cba3ef9f5367193ca722b5c4e8da6d561c9cc98ba7ffbc0688f50ad3fce7ae84d21b69b0df1f24e8ddc533fc97da8441bc1f2031f293999a78520fb3
        self.modulus = p
        for _ in range(100):
            self.step()
    
    def step(self):
        self.state = (self.a * self.state + self.c) % self.modulus

    def random(self):
        self.step()
        return self.state
    
def H(*args):
    sha512 = hashlib.sha512()
    for arg in args:
        sha512.update(str(arg).encode())
    output = unhexlify(sha512.hexdigest())
    return int.from_bytes(output, 'big')


def interactive_mode(p, g, y, lcg):
    print('\n==========Zero knowledge proof of CDH==========')
    r = lcg.random()
    a = pow(g, r, p)
    print(f'a = {a}')
    print('Give me the challenge')
    try:
        c = int(input('c = '))
    except:
        print('Invalid input.')
        exit(1)
    w = c * x + r
    print(f'w = {w}')

def non_interactive_mode(p, g, y):
    print('\n==Non-Interactive Zero knowledge proof of CDH===')
    r = H(flag3)
    a = pow(g, r, p)
    print(f'a = {a}')
    c = H(p, g, y, a)
    w = c * x + r
    print(f'w = {w}')

if __name__ == "__main__":
    alarm(100)
    mode = input('Interactive mode (y/n)? ')
    if mode == "Y" or mode == "y":
        p, g = pk1['p'], pk1['g']
        lcg = linear_congruential_generator(p)
        x = bytes_to_long(flag2)
        y = pow(g, x, p)
        assert y == pk1['y']
    else :
        p, g = pk2['p'], pk2['g']
        x = bytes_to_long(flag3)
        y = pow(g, x, p)
        assert y == pk2['y']
    
    print('My public key:')
    print(f'p = {p}')
    print(f'g = {g}')
    print(f'y = {y}')
        
    if mode == "Y" or mode == "y":
        while True:
            interactive_mode(p, g, y, lcg)
    else:
        non_interactive_mode(p, g, y)
