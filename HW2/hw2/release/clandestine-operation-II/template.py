from pwn import *

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
    # msg = header_signature() + header_type(1) + header_flags(2148041367)
    msg = hex(int.from_bytes(header_signature(), byteorder='big'))[2:]
    + hex(int.from_bytes(header_type(1), byteorder='little'))[2:] + hex(int.from_bytes(header_flags(394397824), byteorder='little'))[2:]
    return msg

def parse_type2_msg(msg):
    msg_hex = hex(int.from_bytes(msg, byteorder='little'))
    print(msg_hex)
    type = msg_hex[8:12]
    assert type == 2, "not type 2"
    challenge = msg_hex[24:32]
    return challenge

def gen_type3_msg():
    msg = header_signature() + header_type(3)
    # TODO
    pass

r = remote('cns.csie.org', 44397)
r.interactive()