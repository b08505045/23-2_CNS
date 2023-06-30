#! /usr/bin/env python3

from utils import ElGamal
from secret import flag1, myLuckyNumber
import signal

def alarm(second):
    def handler(signum, frame):
        print('Timeout!')
        exit()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(second)


def Setup():
    elg = ElGamal()
    elg.print_pubkey()
    message = f'flag: {flag1}'
    assert len(message) <= 50
    c1, c2 = elg.Encrypt(myLuckyNumber, message.encode())
    print('Try to decrypt it!')
    print(f'cipher = {c1, c2}')
    return elg

if __name__ == "__main__":
    elg = Setup()
    while True:
        alarm(100)
        choice = input('Do you want to encrypt something? (y/n): ').strip()
        if choice == 'y':
            message = input('Give me your message: ').strip()
            ct = elg.Encrypt(myLuckyNumber, message.encode())
            print( f"Your cyphertext { ct }" )
        else:
            print('bye')
            break
    
