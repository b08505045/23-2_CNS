import json
import secret
from DB import users_ntlm_hashes
from NTLM_package import *

def shell(ntlm_hash):
    while True:
        command = input('>>> ').strip('\n')
        if standard_ntlmv2_client_signing_verification(command.encode()):
            if command == 'opensesame':
                if ntlm_hash == users_ntlm_hashes['Azar']:
                    msg = 'Nahida: ' + secret.flag2
                else:
                    msg = 'Permission denied'
                sig = standard_ntlmv2_server_signing(msg.encode())
                print(msg)
                print(sig)
            elif command == 'logout':
                return
            else:
                msg = 'Command not found'
                sig = standard_ntlmv2_server_signing(msg.encode())
                print(msg)
                print(sig)
        else:
            msg = 'Session security check failed'
            sig = standard_ntlmv2_server_signing(msg.encode())
            print(msg)
            print(sig)
            exit(255)

def login():
    username = input("Username: ").strip('\n')
    if username not in users_ntlm_hashes:
        print("User does not exist")
        return
    ntlm_hash = users_ntlm_hashes[username]
    if standard_ntlmv2_authentication(ntlm_hash): 
        print(f'Welcome, {username}.')
        if username == 'Azar':
            print(secret.flag1)
        prepare_session_security()
        shell(ntlm_hash)

def menu():
    print(f"{' Control Panel ':=^40}")
    print(' 1. Login')
    print(' 2. Power off')
    print(f"{'':=^40}")

if __name__ == '__main__':
    print('By some means you successfully cracked the database and some data leaked...')
    hashes = dict()
    for name, ntlm_hash in users_ntlm_hashes.items():
        hashes[name] = hexlify(ntlm_hash).decode()
    print(json.dumps(hashes))

    while True:
        menu()
        try:
            choice = int(input('>>> '))
            assert choice in [1, 2]
            if choice == 1:
                login()
            else:
                exit(255)
        except:
            print('Invalid input')
        
            