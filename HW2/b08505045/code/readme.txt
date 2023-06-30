TLS :
1.cd into the code/TLS, run openssl s_client -connect cns.csie.org:12345 -cert Eve.crt -key Eve.key
2.enter pass phrase: abc2934182
3.login as username: Alice413
4.enter password: dogsarecute
5.enter command: "Flag...plzzzzz...", and you will get the flag.
Note : Fermat_factorization.py is just a demonstration to get server's private key from its public key, and we can use server's private key to generate private.pem and add it to wireshark to get decrypted packet.

Little Knowledge Proof:
(a)
1. connect to Alice and Bob at the same time, both in interactive mode.
2. copy a from Alice and send it to Bob.
3. copy c from Bob and send it to Alice.
4. copy w from Alice and send it to Bob, and you will get the flag.
(b)
simply run LCG.py in the Little_Knowledge_Proof folder and you will get the flag.
(c)
I currently can only factorize the group order, but can't implement Pohlig–Hellman algorithm to get x. Simply run pohlig.py in the Little_Knowledge_Proof folder and will get the factorization.

Clandestine Operation II:
(c)
Simply run Clandestine.py in the Clandestine_OperationII folder and will get the flag 1.
(d)
Can't pass the security check yet.

So Anonymous, So Hidden:
(a)Simply run mix1.py and will get the flag, this may take a while.
(b)Simply run mix2.py and will get the flag.
