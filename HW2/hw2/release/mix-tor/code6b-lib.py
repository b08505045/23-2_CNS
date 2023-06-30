import hmac
import hashlib
import secrets
from cipher import StreamCipher, PublicKeyCipher, randbytes


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
        # RSA
        one_time_key = PublicKeyCipher.decrypt(sk, tmp)
        # one-time pad
        return StreamCipher.decrypt(one_time_key, cipher)[:40].strip(b'\x00')

    def decrypt_server(self, sk):
        assert len(self.data) == 400
        tmp, cipher = self.data[:32], self.data[32:]
        one_time_key = PublicKeyCipher.decrypt(sk, tmp)
        tmp = StreamCipher.decrypt(one_time_key, cipher)
        send_to, next_cipher = int(tmp[:20]), (tmp[20:] + randbytes(52))
        return send_to, Packet(next_cipher)


class Server:
    def __init__(self, sk):
        self.sk = sk
        self.recv_buffer = []

    def recv(self, packet: Packet):
        self.recv_buffer.append(packet)
        if len(self.recv_buffer) >= 3:
            self.recv_buffer, processing_buffer = [], self.recv_buffer
            for packet in processing_buffer:
                send_to, next_packet = packet.decrypt_server(self.sk)
                self.send_to_server(send_to, next_packet)

    def send_to_server(self, target, packet):
        pass


# password = 'SecREt01'
# unicode_password = password.encode('utf-16be')
# print(unicode_password.hex())


challenge = '0123456789abcdef'
nonce = 'ffffff0011223344'
# Define the message to be hashed
message = bytes.fromhex('53006500630052004500740030003100')
# Create an MD4 hash object
md4 = hashlib.new('md4')

# Add the message to the hash object
md4.update(message)

# Get the hexadecimal representation of the hash digest
md4_hash = md4.hexdigest()

print(f'md4 hash : {md4_hash}')

message = bytes.fromhex('550053004500520044004f004d00410049004e00')
key = bytes.fromhex(md4_hash)

# Calculate HMAC-MD5
hmac_md5 = hmac.new(key, message, hashlib.md5).hexdigest()
print(hmac_md5)

key = bytes.fromhex(hmac_md5)
message = bytes.fromhex(challenge + nonce)
hmac_md5 = hmac.new(key, message, hashlib.md5).hexdigest()
print(hmac_md5)

LMV2_response = hmac_md5 + nonce

# NTLMv2 response ------------------------------------------------------------------------------------------------

#      blob sign  + reserv val +  timestamp                 +  unknown        + unknown
target_information = '02000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000'

blob = '01010000' + '00000000' + '0090d336b734c301' + nonce + '00000000' + target_information + '00000000'
message = bytes.fromhex(challenge + blob)
hmac_md5 = hmac.new(key, message, hashlib.md5).hexdigest()
print(hmac_md5)
NTLMv2_response = hmac_md5 + blob

# str = '4e544c4d5353500002000000030003003800000015008a60e5a33dc26b1c45fa0000000000000000270027003b000000ffffffff0000000f434e5301000300434e5304000800637369652e6f726703000c00636e732e637369652e6f726700000000'
# print(len(str))

# offset = '38000000'
# offset_byte = bytes.fromhex(offset)
# print(int.from_bytes(offset_byte, byteorder='little'))

str = 'DOMAIN'
print(str.encode('utf-16be').hex())
