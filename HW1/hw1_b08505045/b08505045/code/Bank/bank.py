import urllib.request
from hashlib import sha1
from pwn import *

def sha1(s) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    h = hashlib.sha1()
    h.update(s)
    return h.digest()

print('wait a second...')
# two same sha-1 hash files
url1 = "https://shattered.io/static/shattered-1.pdf"
url2 = "https://shattered.io/static/shattered-2.pdf"

# read files from url
file1, headers = urllib.request.urlretrieve(url1)
file2, headers = urllib.request.urlretrieve(url2)

with open(file1, "rb") as f:
    name1_1 = f.read()

with open(file2, "rb") as f:
    name1_2 = f.read()

secret = b"I love CNS"

name2_1 = name1_1 + secret
name2_2 = name1_2 + secret

print(type(name1_1))

# delete donwloaded files
os.remove(file1)
os.remove(file2)



r = remote('cns.csie.org', 44377)

# register two accounts with same sha1
r.sendlineafter('Your choice: '.encode(), '1'.encode())
r.sendlineafter('Username: '.encode(), name1_1)             # account 1
r.recvuntil('place: '.encode())

password = r.recvline()[:-1]

r.sendlineafter('Your choice: '.encode(), '1'.encode())
r.sendlineafter('Username: '.encode(), name1_2)             # account 2
r.sendlineafter('Your choice: '.encode(), '2'.encode())

# log in
r.sendlineafter('Username: '.encode(), name1_1)
r.sendlineafter('Passkey in Base64: '.encode(), password)
r.sendlineafter('Your choice: '.encode(), '2'.encode())     # buy flag 1 with $20
r.recvuntil('422105\n'.encode())

# print message with successful purchase of flag 1
message = r.recvline()
print(f'message : {message}')

# log out
r.sendlineafter('Your choice: '.encode(), '1'.encode())
input('enter anything to create new 2 accoutns: ')
print('wait a second...')

# register new two accounts appended with "I love CNS"
r.sendlineafter('Your choice: '.encode(), '1'.encode())
r.sendlineafter('Username: '.encode(), name2_1)             # account 1
r.recvuntil('place: '.encode())

password = r.recvline()[:-1]

r.sendlineafter('Your choice: '.encode(), '1'.encode())
r.sendlineafter('Username: '.encode(), name2_2)             # account 2
r.sendlineafter('Your choice: '.encode(), '2'.encode())

# log in
r.sendlineafter('Username: '.encode() , name2_1)
r.sendlineafter('Passkey in Base64: '.encode() , password)
r.sendlineafter('Your choice: '.encode(), '3'.encode())     # buy flag 2 with $30
r.recvuntil('EOF\n'.encode())

# print message with successful purchase of flag 2
message = r.recvline()
print(f'message : {message}')