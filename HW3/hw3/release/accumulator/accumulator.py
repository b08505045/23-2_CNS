from Crypto.Util.number import getPrime, isPrime, GCD, bytes_to_long, long_to_bytes
from random import randrange
from hashlib import sha256

class RSA_Accumulator:
    def __init__(self, Nbits):
        self.Setup(Nbits)       # Run Trusted Setup to get the N of a RSA group
        self.memberSet = []     # The memberSet S

    def Setup(self, Nbits):
        '''
        Set up the RSA Group and generate a generator g.
        * RSA Accumulator needs trusted setup from third-party.
          -> The factor of N should not be known by anyone.
        '''
        self.N = getPrime((Nbits+1)//2) * getPrime((Nbits+1)//2)
        
        g = randrange(1,self.N)
        while (GCD(g, self.N) != 1 or g == 1):
            g = randrange(1,self.N)        
        self.g = g

    def xgcd(self, a, b):
        """return (x, y) such that a*x + b*y = gcd(a, b)"""
        x0, x1, y0, y1 = 0, 1, 1, 0
        while a != 0:
            (q, a), b = divmod(b, a), a
            y0, y1 = y1, y0 - q * y1
            x0, x1 = x1, x0 - q * x1
        return x0, y0
    
    @staticmethod
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
    
    def add(self, content):
        '''
        Add an content to memberSet
        '''
        s = self.HashToPrime(content)
        self.memberSet.append(s)

    def Digest(self):
        '''
        Digest all the contents in memberSet.
        '''
        digest = self.g
        # TODO: Digest all the elements in memberSet.
        #       Hint: digest = g ^ ( product of "all the primes in memberSet"  )
        product = 1
        for member in self.memberSet:
            product = product * member % self.N
        digest = pow(self.g, product, self.N)
        return digest

    def MembershipProof(self, content, d):
        m = self.HashToPrime(content)
        if m not in self.memberSet: raise ValueError
        
        proof = self.g
        # TODO: Make a membership proof for m.
        #       Hint: proof = g ^ ( product of "all the primes in memberSet except for m" )
        product = 1
        for member in self.memberSet:
            if member != m:
                product = product * member % self.N
        proof = pow(self.g, product, self.N)
        return proof

    def MembershipVerification(self, N, content, d, proof) -> bool:
        m = self.HashToPrime(content)
        # TODO: Verify the membership proof of m.
        #       Hint: Check "proof ^ m == d"
        return pow(proof, m, self.N) == d

    def NonMembershipProof(self, content):
        m = self.HashToPrime(content)
        if m in self.memberSet: raise ValueError
        
        # TODO: Make a non-membership proof for m.
        #       Hint: let delta = product of "all the primes in memberSet except for m.
        #             find (a, b) satisfy a * m + b * delta = 1 
        #             proof = (g^a, b)
        #             p.s. since gcd(m, delta) == 1, you can use xgcd(Extended Euclidean algorithm) to find (a, b)
        delta = 1
        for member in self.memberSet:
            if member != m:
                delta = delta * member % self.N
        a, b = self.xgcd(m, delta)
        print(f'xgcd : {a*m + b*delta == 1}')
        proof = (pow(self.g, a, self.N), b)
        return proof
    
    def NonMembershipVerification(self, N, content, d, proof, g):
        m = self.HashToPrime(content)
        # TODO: Verify the non-membership proof of m.
        #       Hint: Check "(g^a)^m * digest^b == g^(a*m + b*delta) == g"
        return (pow(proof[0], m, self.N) * pow(d, proof[1], self.N)) % self.N == self.g

if __name__ == "__main__":
    
    A = RSA_Accumulator(1024)
    A.add(b"Hello!")
    A.add(b"Test!")
    A.add(b"CNS")
    A.add(b"accumulatorrrrrr")
    
    d = A.Digest()
    N = A.N
    g = A.g
    proof = A.MembershipProof(b"accumulatorrrrrr", d)
    if A.MembershipVerification(N, b"accumulatorrrrrr", d, proof):
        print( "'accumulatorrrrrr' is in the set." )
    else:
        print( "The proof is wrong." )

    proof = A.NonMembershipProof(b"QAQ")
    if A.NonMembershipVerification(N, b"QAQ", d, proof, g):
        print( "'QAQ' is not in the set." )
    else:
        print( "The proof is wrong." )