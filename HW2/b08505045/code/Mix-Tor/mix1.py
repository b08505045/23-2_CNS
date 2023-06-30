import secrets
from cipher import StreamCipher, PublicKeyCipher, randbytes
from pwn import *
import base64
import binascii
import math
import random

print(str)
def i2b(n): # int to bytes
    return f'{n:20d}'.encode()


class Packet:
    def __init__(self, data):
        assert len(data) == 400
        self.data = data

    def __repr__(self):
        return f'Packet({self.data})'

    @staticmethod

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


r = remote('cns.csie.org', 12804)
r.recvuntil('Your public key is ('.encode())
pk = (int(r.recvuntil(', '.encode())[:-2].decode()), int(r.recvuntil(')'.encode())[:-1].decode()))
r.recvuntil('Your private key is ('.encode())
sk = (int(r.recvuntil(', '.encode())[:-2].decode()), int(r.recvuntil(')'.encode())[:-1].decode()))

print(f'pk : {pk}')
print(f'sk : {sk}')

for i in range(6):
    ret = r.recvline()
    if i == 6: print(ret)

buffer = []

# start to receive packet
print('start receiving packet : ')
index = 0
i = 0
while True:
    data = r.recvline().decode().strip()
    if data[:3] == 'CNS':
        break
    data_byte = bytes.fromhex(data)
    packet = Packet(data_byte)
    send_to, next_packet = packet.decrypt_server(sk)
    buffer.append((send_to, next_packet))
    
    if len(buffer) == 100:
        print('\n\nsend : \n')
        random.shuffle(buffer)
        for buf_i in buffer:
            print(f'{index} : {buf_i[0]}', end = ', ')
            index += 1
            r.sendline(f"({buf_i[0]}, {buf_i[1].data.hex()})".encode())
        index = 0
        buffer.clear()
        print('\nnext run\n')

print(data)
r.interactive()

