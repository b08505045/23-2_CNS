from Crypto.Util.number import getPrime, isPrime, bytes_to_long, long_to_bytes
from random import randint

class ElGamal:
    def __init__(self):
        # Create the public key.
        self.P = 229427426007004641058038399605893431891338652544880488643534649263550827812892013492489412406570250351976852154191427816707204012255764549959937503449437748973977415513106105897497757095728051081468939079966553921958218909428521019515171147734090784426719929697847543345936614548176336768375245642108499733879
        # The public key P is chosen by the following code.
        ''' 
        while True:
            self.P = getPrime(1024) * 2 + 1
            if isPrime(self.P): break
        '''
        # It takes about 2 minutes to generate such a P.
        # The generation of P is not the key point of this question,
        #     so you can easily skip this part to save time.
        # However, if you find any attacks to this prime, please let me know! XD
        
        # Choose a generator.
        while True:
            self.g = randint(1, self.P-1) 
            if pow(self.g, 2, self.P) != 1 and pow(self.g, (self.P-1)//2, self.P) != 1:
                # Just make sure that the generator g be a primitive root of P.
                break
        
        self.sk = randint(1, self.P-1)
        self.pk = pow(self.g, self.sk, self.P)

    def print_pubkey(self):
        print('public key:')
        print(f'P = {self.P}')
        print(f'g = {self.g}')

    def Encrypt(self, y, message):
        message = bytes_to_long(message)
        return ( pow(self.g, y, self.P),
                 pow(self.pk, y, self.P) * message % self.P )
    
    def Decrypt(self, c1, c2):
        pt = pow(c1, -self.sk, self.P) * c2 % self.P
        message = long_to_bytes(pt)
        return message
