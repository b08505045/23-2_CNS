Smart contract : To solve questions except for challenge 0 and 1, first deploy the Hack.sol.

0.Simply interact with CNSChallenge and type my ID.

1. Send 1 ether from my wallet to CNSChallenge.

2. Run getPrivate.js to get the value of "next", then run setNext(_next) in Hack.sol with _next = the value got from getPrivate.js, to initialize "next, and then run random() in Hack.sol to get the value of random number.

3. Simply run ReentryAttack() in Hack.sol

4. Simply run getToken() in Hack.sol

5. Simply run stealToken(_to, spender) in Hack.sol with _to = CNSToken's address and spender = my wallet's address


Accumulator :
1. Simply run accumulator.py to get the result.
2. Simply run code4.py to get two flags.
