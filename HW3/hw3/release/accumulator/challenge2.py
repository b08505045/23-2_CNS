#! /usr/bin/env python3
from accumulator import RSA_Accumulator, xgcd
from Crypto.Util.number import bytes_to_long
from hashlib import sha256
from secret import flag3
import signal

def alarm(second):
    def handler(signum, frame):
        print('Timeout!')
        exit()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(second)

class Division_Intractable_RSA_Accumulator(RSA_Accumulator):
    @staticmethod
    def HashToPrime(content):
        '''
        No longer hash to prime.
        Just hash the content to a big number and believe there is a prime in this number.
        '''
        return bytes_to_long( sha256(content).digest()[:16] )
    
    # FYI. The NonMembership proof of Division Intractable version needs little revision as follow.
    # You do not need these parts in this problem. Feel free to skip these parts.
    def NonMembershipProof(self, content):
        m = self.HashToPrime(content)
        if m in self.memberSet: raise ValueError
        
        delta = 1
        for s in self.memberSet:
            delta *= s

        gcd, a, b = xgcd( m, delta )
        if gcd == m:
            # m must be a member!
            raise ValueError
        
        return pow(self.g, a, self.N), b, gcd
    
    @staticmethod
    def NonMembershipVerification(N, content, d, proof, g, gcd):
        q, b = proof
        m = RSA_Accumulator.HashToPrime(content)
        return m % gcd == 0 and (pow(q, m, N) * pow(d, b, N)) % N == pow(g, gcd, N)

if __name__ == "__main__":
    acc = Division_Intractable_RSA_Accumulator(1024)
    print( "I have an accumulator with Division-Intractable hash on the RSA Group with: ")
    print(f"N = {hex(acc.N)}")
    print(f"g = {hex(acc.g)}")
    print( "Prove me some incredible things!")
    digest = acc.Digest()
    members = set()
    for _ in range(30):
        alarm(100)
        print( f"\nOptions:")
        print( f"[0] Prove membership for something not being member.")
        print( f"[1] Add a member.")
        print( f"[2] Exit.")
        choice = input('Enter your choice? [0,1,2] ').strip()
        if choice == '0':
            message = input('Give me your message: ').strip()
            proof = int(input('Give me your membership proof for the message: ').strip())
            if acc.MembershipVerification(acc.N, message.encode(), digest, proof) \
                and message not in members:
                print(f"Cool! Give you the flag. {flag3}")
            else:
                print("Nothing special.")

        elif choice == '1':
            message = input('Give me your message: ').strip()
            if message in members:
                print("Already in members!")
                continue
            print(message.encode())
            members.add(message)
            acc.add(message.encode())
            digest = acc.Digest()
            print(f"New digest: {hex(digest)}")
        else:
            print('bye~')
            break
    
