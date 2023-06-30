# cns.csie.org 44398

from pwn import *
import base64
import binascii
import math

def caesar_cipher(text):
    for key in range(26):
        plaintext = ''
        for char in text:
            if char.isalpha():
                if char.islower():
                    char = chr((ord(char) - key - 97) % 26 + 97)
                else:
                    char = chr((ord(char) - key - 65) % 26 + 65)
            plaintext += char
        print(plaintext)

def fence_cipher(text):
    length = len(text)
    for key in range(2, length):
        rail = [ [0]*length for i in range(key)] # rail is (key)*(length) array
        row = col = 0
        is_down = True
        for i in range(length):
            if not row: is_down = True
            if row == key - 1: is_down = False
            rail[row][col] = '*'
            col += 1
            row = (row + 1) if is_down else (row - 1)

        index = 0
        for i in range(key):
            for j in range(length):
                if rail[i][j] =='*' and index < length:
                    rail[i][j] = text[index]
                    index += 1
        
        plaintext = ''
        row = col = 0
        for i in range(length):
            if not row: is_down = True
            if row == key - 1: is_down = False
            if rail[row][col] != '*':
                plaintext += rail[row][col]
                col += 1
            row = (row + 1) if is_down else (row - 1)
        
        print(plaintext)

def OTP(b64_c1, m1, b64_c2):
    bytes_c1 = base64.b64decode(b64_c1)
    bit_str_c1 = ''.join([bin(byte)[2:].zfill(8) for byte in bytes_c1])

    bytes_m1 = m1.encode()
    bit_str_m1 = ''.join([bin(byte)[2:].zfill(8) for byte in bytes_m1])

    bytes_c2 = base64.b64decode(b64_c2)
    bit_str_c2 = ''.join([bin(byte)[2:].zfill(8) for byte in bytes_c2])

    length_c1 = len(bit_str_c1)
    length_m1 = len(bit_str_m1)
    length_c2 = len(bit_str_c2)

    key = ''
    for i in range(length_c1):
        a = int(bit_str_c1[i])
        b = int(bit_str_m1[i])
        key += '0' if not (a ^ b) else '1'

    length = length_c1 if length_c1 < length_c2 else length_c2
    bit_str_m2 = ''
    for i in range(length):
        a = int(key[i])
        b = int(bit_str_c2[i])
        bit_str_m2 += '0' if not (a ^ b) else '1'

    hex_m2 = hex(int(bit_str_m2, 2))[2:]
    bytes_m2 = bytes.fromhex(hex_m2)
    m2 = bytes_m2.decode()
    print(m2)
    return m2
# enter caesar cipher
str = input('enter ciphertext for caesar : ')
print('\n')
caesar_cipher(str)

# enter fence cipher
print('\n')
str = input('enter ciphertext for fence : ')
print('\n')
fence_cipher(str)

# enter OTP cipher
b64_c1 = input('\n\nenter b64_c1 : ').encode()
m1 = input('enter m1 : ')
b64_c2 = input('enter b64_c2 : ').encode()
print('\n')
OTP(b64_c1, m1, b64_c2)








# r = remote('cns.csie.org', 44398)
# r.recvuntil('[?] ')
# txt = r.recvline().decode()
# # print(txt)
# a, b = int(txt[0]), int(txt[4])
# # print(a + b)

# r.sendlineafter('>>> ', str(a + b))
# r.recvuntil('! "')
# txt = r.recvuntil('!').decode()
# r.sendlineafter('>>> ', txt)
# r.recvuntil('c = \'')
# txt = r.recvuntil('\'').decode()
# r.recvline()
# r.sendlineafter('>>> ', txt)
# r.interactive()
