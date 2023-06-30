#! /usr/bin/env python3
from accumulator import RSA_Accumulator
from secret import flag1, flag2
import signal

def alarm(second):
    def handler(signum, frame):
        print('Timeout!')
        exit()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(second)


def bad_setup():
    acc = RSA_Accumulator(1024)
    
    # Oops, the private key of RSA is leaked......
    acc.N = 0xfe7fa2d93be7396c7172a7186f4e561949f53e436a7ed65da22786637b7e76081f65b972be84ea612787a07878c1bf9454edf81059f84158efe34b4207f96d71 \
             * 0xb76082ea921f3d4729e59d765ff014ad745b6421f1bacc359417e0c2a1aaa318bd96ba0f6476e09bd1db72fa4dfc7fa5aa0ee1bef7bc4f268fb42673e539d3b1
    acc.g = 0xa8ccac65582e3accb0e246c4d79b9d054e85e086b6d5c48df6f79bf60ad4c77d797ba7fdba0b0a83071f16e427bff7d7d7ab768d4694f90a5eef5278201f8848221b998a7f5322a66f9eac87d5d4f801a2af3fa7a983f9678732b6b16b40c2e2b8e5612e9834f2e64b0aa91f91c479113b0d263dc81572f5b5d367d4911008cd
    
    acc.add(b"Member0")
    acc.add(b"Member1")
    acc.add(b"Member2")
    digest = acc.Digest()
    return acc, digest

if __name__ == "__main__":
    acc, digest = bad_setup()
    print( "I have an accumulator on the RSA Group with: ")
    print(f"N = {hex(acc.N)}")
    print(f"g = {hex(acc.g)}")
    
    print( "Also, I have a digest: ")
    print(f"d = {hex(digest)}")
    print( "Prove me some incredible things!")
    while True:
        alarm(100)
        print( f"\nOptions:")
        print( f"[0] Prove membership for something not being member.")
        print( f"[1] Prove non-membership for something being member.")
        print( f"[2] Exit.")
        choice = input('Enter your choice? [0,1,2] ').strip()
        if choice == '0':
            message = input('Give me your message: ').strip()
            proof = int(input('Give me your membership proof for the message: ').strip())
            if acc.MembershipVerification(acc.N, message.encode(), digest, proof) \
                and message not in ["Member0", "Member1", "Member2"] :
                print(f"Cool! Give you the flag. {flag1}")
            else:
                print("Nothing special.")

        elif choice == '1':
            message = input('Give me your message: ').strip()
            print('Give me your non-membership proof for the message:')
            g_a = int(input('g^a = ').strip())
            b = int(input('b = ').strip())
            proof = (g_a, b)
            if acc.NonMembershipVerification(acc.N, message.encode(), digest, proof, acc.g) \
                and message in ["Member0", "Member1", "Member2"] :
                print(f"Cool! Give you the flag. {flag2}")
            else:
                print("Nothing special.")
        else:
            print('bye~')
            break
    
