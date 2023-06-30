import secrets
from cipher import StreamCipher, PublicKeyCipher, randbytes
from pwn import *
import base64
import binascii
import math
import random


def i2b(n): # int to bytes
    return f'{n:20d}'.encode()

class Packet:
    def __init__(self, data):
        assert len(data) == 400
        self.data = data

    def __repr__(self):
        return f'Packet({self.data})'

    @staticmethod
    def create(message, send_to: int, pk):
        assert len(message) <= 40
        message = message.ljust(400, b'\x00')
        message = PublicKeyCipher.encrypt(pk, send_to) + StreamCipher.encrypt(send_to, message)
        data = message[:400] # TODO: create the correct data
        return Packet(data)

    def add_next_hop(self, target, pk):
        msg = i2b(target) + self.data[:-52]
        one_time_key = 5
        msg = PublicKeyCipher.encrypt(pk, one_time_key) + StreamCipher.encrypt(one_time_key, msg)
        assert len(self.data) == 400
        return msg

    def decrypt_client(self, sk):
        assert len(self.data) == 400
        tmp, cipher = self.data[:32], self.data[32:]
        one_time_key = PublicKeyCipher.decrypt(sk, tmp) # derive m
        return StreamCipher.decrypt(one_time_key, cipher)[:40].strip(b'\x00') # use m to xor one-time pad

    def decrypt_server(self, sk):
        assert len(self.data) == 400
        tmp, cipher = self.data[:32], self.data[32:]
        one_time_key = PublicKeyCipher.decrypt(sk, tmp)
        tmp = StreamCipher.decrypt(one_time_key, cipher)
        send_to, next_cipher = int(tmp[:20]), (tmp[20:] + randbytes(52))
        return send_to, Packet(next_cipher)

message = b"Give me flag, now!"
pk = {}

# get servers' pk (pk[3] is Bob)
r = remote('cns.csie.org', 12805)
for i in range(4):
    r.recvuntil('is ('.encode())
    pk[i] = (int(r.recvuntil(', '.encode())[:-2].decode()), int(r.recvuntil(')\n'.encode())[:-2].decode()))

# print(f'The public key of server0 is {pk[0]}')
# print(f'The public key of server1 is {pk[1]}')
# print(f'The public key of server2 is {pk[2]}')
# print(f'The public key of Bob is {pk[3]}')

route = []
r.recvuntil('should be ['.encode())

for i in range(5):
    route.append(int(r.recvuntil(', '.encode()).decode()[:-2]))
route.append(3)
# print(f'route : {route}')

# create packet
packet = Packet.create(message, 3, pk[3])
# add hop
length = len(route)
for i in range(length - 1, 0, -1):
    packet.data = packet.add_next_hop(route[i], pk[route[i - 1]])
packet_test = Packet(bytes.fromhex(packet.data.hex()))

r.sendlineafter('> '.encode(), packet.data.hex().encode())
r.recvuntil('Bob: '.encode())
flag = r.recvline()[:-1].decode()
print(f'flag : {flag}')


