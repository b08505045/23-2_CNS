# CBC mode paddign oracle attack

from pwn import *
import base64
import binascii
import math

# prefix : job title:Grand Disciplinary Officer||name:Cyno||secret word:
id = '70309f98653e87df804263d5a0348f115c36bc7c2cddfe02ffd44528083635404815ed8c0f14ad8cbbb1c7bc12bf21725fa15c0e7ba326e433ec41ddfaf41d27aa18ce4381a61d187ecbdcc9740747d300b7f354bb68139f2306508a06a04fbe'

length = len(id)                                                # 192
block_size = 16
num_of_block = length // (block_size * 2)                       # 6 blocks
determined_blocks = []                                          # determined blocks
is_find = False                                                 # use when the predict_byte = padding_byte

# last 2nd block
str_c1 = id[128:160]
byte_c1 = bytes.fromhex(str_c1)

temp_str_c1 = str_c1
temp_byte_c1 = byte_c1

# print('\nconnect-----------------------------------------------------------------------------------------------------------------------------')
r = remote('cns.csie.org', 44399)
r.recvuntil('========================================'.encode())
r.sendlineafter('Your choice: '.encode(), '2'.encode())

print('\nwait a second...')


for run in range(1,4):
    determined_bytes = []                                       # bytes that have been determined in current run
    target_block = num_of_block - run                           # current modified blcok, start from 5, 4, 3... 
    str_c1 = id[(target_block - 1) * 32:target_block * 32]      # [128:160], [96:128]...

    byte_c1 = bytes.fromhex(str_c1)
    temp_str_c1 = str_c1
    temp_byte_c1 = byte_c1

    for i in range(1,17):
        # print(f'\n{i}------------------------------------------------------------------------------------------------------------------------------------------------------------')
    
        pad_byte = (i).to_bytes(1, 'big')                       # current padding byte
        predict_index = block_size - i                          # current index of z_{-i} 
        target_byte = byte_c1[predict_index:predict_index + 1]  # current b_{-1} 

        determined_bytes_len = len(determined_bytes)            # number of current determined bytes
        constructed_bytes = b''                                 # constructed from determined_bytes

        # construct set of bytes that have been determined
        for j in range(determined_bytes_len):
            index = block_size - determined_bytes_len + j 
            xor_byte = bytes([a ^ b for a, b in zip(byte_c1[index:index + 1], determined_bytes[j])])
            constructed_bytes += bytes([a ^ b for a, b in zip(xor_byte, pad_byte)])

        # guess the ith to the last byte of mi
        for j in range(256):
            # predict_byte = padding_byte
            if (i == j):
                continue

            r.sendlineafter('Your choice: '.encode(), '1'.encode())

            predict_byte = (j).to_bytes(1, 'big')
            xor_byte = bytes([a ^ b for a, b in zip(target_byte, predict_byte)])
            xor_byte = bytes([a ^ b for a, b in zip(xor_byte, pad_byte)])

            if constructed_bytes != b'':
                temp_byte_c1 = byte_c1[0:predict_index] + xor_byte + constructed_bytes
            else:
                temp_byte_c1 = byte_c1[0:predict_index] + xor_byte

            # construct modified block & id
            temp_str_c1 = temp_byte_c1.hex()
            try_id = id[0:(target_block - 1) * 32] + temp_str_c1 + id[target_block * 32:(target_block + 1) * 32]

            r.sendlineafter('Please give me the ID (hex encoded): '.encode(), try_id.encode())
            message = r.recvline()

            # if no padding error then found
            if (message != b'Hint: PADDING ERROR : incorrect padding\n'):
                determined_bytes.insert(0, predict_byte)
                is_find = True
                break
        
        # predict_byte = padding_byte
        if (not is_find):
            determined_bytes.insert(0, pad_byte)
        is_find = False

    block = b''
    for i in range (len(determined_bytes)):
        block += determined_bytes[i]
    determined_blocks.insert(0, block)

res = b''
for i in range(len(determined_blocks)):
    res += determined_blocks[i]

flag1 = (res[13:])[:-6]
print(f'flag1 : {flag1}')

r.sendlineafter('Your choice: '.encode(), '3'.encode())
r.sendlineafter('Your choice: '.encode(), '1'.encode())
r.sendlineafter('word: '.encode(), flag1)



# flag2----------------------------------------------------------------------------------------------------------------------------------------


input('enter anything to continue :')
print('wait a second...')

id_2 = bytes.fromhex('5c36bc7c2cddfe02ffd4452808363540')        # block2 of id
plain_3 = b'icer||name:Cyno|'                                   # original plaintext of block 3
modified_plain_3 = b'icer||name:Azar|'                          # modified plaintext of block 3

middle_3 = bytes([a ^ b for a, b in zip(id_2, plain_3)])
modified_id_2 = bytes([a ^ b for a, b in zip(modified_plain_3, middle_3)])    
modified_plain_3 = bytes([a ^ b for a, b in zip(modified_id_2, middle_3)])    

id_prefix = id[0:32]
id_suffix = id[64:192]

is_find = False                                                 # here is_find indicates found valid id

for i in range(256):
    b1 = (i).to_bytes(1, 'big')
    for j in range(256):
        b2 = b1 + (j).to_bytes(1, 'big')
        for k in range(256):
            b3 = b2 + (k).to_bytes(1, 'big')
            for l in range(256):
                b4 = b3 + (l).to_bytes(1, 'big')
                
                temp_id_2 = binascii.hexlify(modified_id_2[4:]).decode()
                temp_id_2 = binascii.hexlify(b4).decode() + temp_id_2
                modified_id = id_prefix + temp_id_2 + id_suffix

                r.sendlineafter('Your choice: '.encode(), '1'.encode())
                r.sendlineafter('(hex encoded): '.encode(), modified_id.encode())

                message = r.recvline()
                if message[:14] == b'Authentication':
                    continue

                message = r.recvline()
                if message[:8] == b'Welcome!':
                    # print('Great!')
                    is_find = True
                    break

            if is_find == True:
                break
        if is_find == True:
            break
    if is_find == True:
        break

print(f'flag2 : {message[28:-1]}')