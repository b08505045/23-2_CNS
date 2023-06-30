#! /usr/bin/env python3

from utils import ElGamal
from secret import flag2
from random import randint
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
    message = f'flag: {flag2}'
    assert len(message) <= 50
    randomNumber = randint(1, elg.P-1)
    c1, c2 = elg.Encrypt(randomNumber, message.encode())
    print('Try to decrypt it!')
    print(f'cipher = {c1, c2}')
    return elg

if __name__ == "__main__":
    elg = Setup()
    while True:
        alarm(100)
        choice = input('Do you want to tell me something? (y/n): ').strip()
        if choice == 'y':
            c1 = int(input('Give me your c1: ').strip())
            c2 = int(input('Give me your c2: ').strip())
            message = elg.Decrypt(c1, c2)
            if len(message) >= 128:
                print("I cannot understand such a long message.")
            else:
                print("OK, I got it!")
        else:
            print('bye')
            break
    
