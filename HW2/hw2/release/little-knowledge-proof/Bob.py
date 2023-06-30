#! /usr/bin/env python3

import random
from public import pk1, pk2
from secret import flag1
import hashlib
from binascii import unhexlify
import signal

def alarm(second):
    def handler(signum, frame):
        print('Timeout!')
        exit()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(second)

def H(*args):
    sha512 = hashlib.sha512()
    for arg in args:
        sha512.update(str(arg).encode())
    output = unhexlify(sha512.hexdigest())
    return int.from_bytes(output, 'big')

def interactive_mode(p, g, y):
    print('==========Show me your knowledge of CDH==========')
    try:
        a = int(input('a = '))
        assert a > 0 and a < p
    except:
        print('Invalid input.')
        exit(1)
    
    c = random.randint(1, p-2)
    print(f'c = {c}')
    try:
        w = int(input('w = '))
    except:
        print('Invalid input.')
        exit(1)
        
    if pow(g, w, p) == (pow(y, c, p) * a) % p:
        print(f'I think you\'re Alice. Here is the flag: {flag1}')
    else:
        print('Hello stranger~')
    
def non_interactive_mode(p, g, y):
    '''
    This function has no flag, but  
    you are recommanded to learn the non_interactive mode by yourself.
    '''
    print('==========Show me your knowledge of CDH==========')
    try:
        a = int(input('a = '))
        assert a > 0 and a < p
    except:
        print('Invalid input.')
        exit(1)
    
    c = H(p, g, y, a)
    
    try:
        w = int(input('w = '))
    except:
        print('Invalid input.')
        exit(1)
        
    if pow(g, w, p) == (pow(y, c, p) * a) % p:
        print(f'I think you\'re Alice.')
    else:
        print('Hello stranger~')


if __name__ == "__main__":
    alarm(100)
    mode = input('Interactive mode (y/n)? ')
    if mode == "Y" or mode == "y":
        p, g, y = pk1['p'], pk1['g'], pk1['y']
    else :
        p, g, y = pk2['p'], pk2['g'], pk2['y']
    
    print('Alice\'s public key:')
    print(f'p = {p}')
    print(f'g = {g}')
    print(f'y = {y}')
        
    if mode == "Y" or mode == "y":
        while True:
            interactive_mode(p, g, y)
    else:
        non_interactive_mode(p, g, y)
