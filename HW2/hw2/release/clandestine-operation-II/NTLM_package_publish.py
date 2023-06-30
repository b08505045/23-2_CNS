#!/usr/local/bin/python3 -u
# -*- coding: latin-1 -*-
import sys

minimal = [16]

def read_more(f, now, length):
    ret = b""
    length -= now
    now = 0
    while now < length:
        # print (now, length, file=sys.stderr)
        ret += b"\n"
        if now == length - 1:
            break
        ret += f.readline()[:-1]
        now = len(ret)
    return ret


def panic(ret):
    print(ret)
    raise NotImplementedError

def standard_ntlmv2_authentication(password):
    with open(sys.stdin.fileno(), "rb", closefd=False) as f:
        type1_msg = f.readline()[:-1]
        while len(type1_msg) < minimal[0]:
            type1_msg += b"\n" + f.readline()[:-1]
        # ...
    return True

def standard_ntlmv2_client_signing_verification(msg):
    with open(sys.stdin.fileno(), "rb", closefd=False) as f:
        signature = f.readline()[:-1]
        # ...

    if signature == expected_signature:
        return True
    else:
        return False