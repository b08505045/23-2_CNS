#! /usr/bin/env python3

from utils import ElGamal
from secret import flag3
from random import randint
import signal

def alarm(second):
    def handler(signum, frame):
        print('Timeout!')
        exit()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(second)

class threshold_ElGamal(ElGamal):
    def key_distribution(self):
        print('The secret key using the Shamir secret sharing with threshold = 5.')
        print(f'f(x) = ax^4 + bx^3 + cx^2 + dx + sk in Z_p\n')
        p = (self.P - 1) // 2
        a = randint(1, p)
        b = randint(1, p)
        c = randint(1, p)
        d = randint(1, p)
        sk = self.sk  = randint(1, p)
        self.pk = pow(self.g, self.sk, self.P)
        f = lambda x: (a*(x**4) + b*(x**3) + c*(x**2) + d*x + sk) % self.P
        f = lambda x: (a*(x**4) + b*(x**3) + c*(x**2) + d*x + sk) % p
        return {1: f(1), 2: f(2), 3: f(3), 4: f(4), 5: f(5)}

    def PartialDecrypt(self, c1, secret_sharing_sk):
        return pow(c1, secret_sharing_sk, self.P)

def Setup():
    elg = threshold_ElGamal()
    keys = elg.key_distribution()
    elg.print_pubkey()
    message = f'flag: {flag3}'
    assert len(message) <= 50
    randomNumber = randint(1, elg.P-1)
    c1, c2 = elg.Encrypt(randomNumber, message.encode())
    print('Try to decrypt it!')
    print(f'cipher = {c1, c2}')
    return elg, keys

if __name__ == "__main__":
    elg, keys = Setup()
    while True:
        alarm(100)
        choice = input('Do you want to decrypt something? (y/n): ').strip()
        if choice == 'y':
            c1 = int(input('Give me your c1: ').strip())
            i = int(input('Which key do you wnat to use? (1~5): ').strip())
            response = elg.PartialDecrypt(c1, keys[i])
            print(response)
        else:
            print('bye')
            break
