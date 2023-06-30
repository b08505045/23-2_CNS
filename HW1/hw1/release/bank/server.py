import base64
import collections
import hashlib
import io
import select
import random
import sys

from secret import flag1, flag2

balances = collections.defaultdict(int)
keys = {}

NEW_USER_GIFT = 10
CNS_LOVER_BONUS = 5
FLAG1_PRICE = 20
FLAG2_PRICE = 30


def sha1(s) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    h = hashlib.sha1()
    h.update(s)
    return h.digest()


def input_untruncated(prompt: str) -> bytes:
    """Just for handling network I/O"""
    print(prompt, end="")
    buf = io.BytesIO()
    b = sys.stdin.buffer.read1(4096)
    assert buf.write(b) == len(b)
    while (slists := select.select([sys.stdin.fileno()], [], [], 1)) and slists[0]:
        b = sys.stdin.buffer.read1(4096)
        assert buf.write(b) == len(b)
    return buf.getvalue()


def login(username):
    while True:
        h = sha1(username)

        print()
        print(
            f"Welcome back, {username.decode('cp437')}. You have ${balances[h]} in balance"
        )
        print("+--------------------------+")
        print("| 1. Logout                |")
        print(f"| 2. Buy flag 1 with ${FLAG1_PRICE}   |")
        print(f"| 3. Buy flag 2 with ${FLAG2_PRICE}   |")
        print("+--------------------------+")
        print()

        try:
            cmd = int(input("Your choice: "))
        except ValueError:
            print("\nInvalid input\n")
            continue

        match cmd:
            case 1:
                # logout
                break

            case 2:
                # get flag 1
                if balances[h] >= FLAG1_PRICE:
                    balances[h] -= FLAG1_PRICE
                    print(f"\nHere is your flag 1: {flag1}\n")
                else:
                    print(
                        f"\nYou only have ${balances[h]} in your balance. Go earn money\n"
                    )

            case 3:
                # get flag 2
                if balances[h] >= FLAG2_PRICE:
                    balances[h] -= FLAG2_PRICE
                    print(f"\nHere is your flag 2: {flag2}\n")
                else:
                    print(
                        f"\nYou only have ${balances[h]} in your balance. Go earn money\n"
                    )

            case _:
                print("\nInvalid input\n")


def menu():
    print()
    print("Welcome to CNS Bank")
    print(f"A new user will receive ${NEW_USER_GIFT} as your gift")
    print(f"CNS lovers will receive another ${CNS_LOVER_BONUS}")
    print("You will need money to buy the flag")
    print("Try to earn money")

    while True:
        print()
        print("+------------------------+")
        print("| 1. Register a new user |")
        print("| 2. Login               |")
        print("| 3. Quit                |")
        print("+------------------------+")
        print()

        try:
            cmd = int(input("Your choice: "))
        except ValueError:
            print("\nInvalid input")
            continue

        match cmd:
            case 1:
                # register
                username = input_untruncated("Username: ").strip(b"\n")
                if username in keys:
                    print("The username already used, try another")
                    continue

                key = keys[username] = random.randbytes(16)
                print(
                    f"Here is your passkey, store it in a safe place: {base64.b64encode(key).decode()}"
                )
                h = sha1(username)
                balances[h] += NEW_USER_GIFT
                if b"I love CNS" in username:
                    # good students get bonus
                    balances[h] += CNS_LOVER_BONUS

            case 2:
                # login
                username = input_untruncated("Username: ").strip(b"\n")
                key = input("Passkey in Base64: ").strip("\n")
                try:
                    key = base64.b64decode(key)
                except:
                    print("\nInvalid input")
                    continue

                if key == keys.get(username):
                    print("\nLogin success")
                    login(username)
                else:
                    print("\nIncorrect username or key")

            case 3:
                # quit
                print("\nGood bye")
                break

            case _:
                print("\nInvalid input")


def main():
    sys.stdout = io.TextIOWrapper(
        open(sys.stdout.fileno(), "wb", buffering=0), write_through=True
    )
    menu()


if __name__ == "__main__":
    main()
