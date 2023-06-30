import random
from cryptoFunc import *
from motivationalQuotes import *

def askNahida():
    haveQuestion = True

    while haveQuestion:
        print('========================================================')
        print(' Dear traveler, is there anything I can do to help you?')
        print(' 1. Tell me something about the ID card')
        print(' 2. Please encourage me')
        print(' 3. I have no question')
        print('========================================================')

        choice = input('Your choice: ').strip()
        try:
            choice = int(choice)
        except:
            print("I don't know what you mean...")
            continue

        if choice == 1:
            ID = input('Please give me the ID (hex encoded): ').strip()
            try:
                decrypt(ID)
                print('Hint: It seems feasible...')
            except Exception as e:
                if e.__class__.__name__ == 'UnicodeDecodeError':
                    print('Hint:', 'Not a valid ID...')
                else:
                    print('Hint:', e)

        elif choice == 2:
            idx = random.randint(0, len(quotes)-1)
            quote  = quotes[idx]
            print(quote)

        elif choice == 3:
            print('Bye~ May wisdom always be with you!')
            haveQuestion = False

        else:
            print("I don't know what you mean...")

def beforeEnterAkademiya():
    print(f"{' Akademiya ':=^40}")
    print(' What do you want to do?')
    print(' 1. Enter Akademiya')
    print(' 2. Ask Nahida for help')
    print(' 3. Give up')
    print(f"{'':=^40}")

def beforeEnterSurasthana():
    print(f"{' Sanctuary of Surasthana ':=^40}")
    print('Warning: Only Azar can enter this place!')
    print('-'*40)
    print(' What do you want to do?')
    print(' 1. Enter Sanctuary of Surasthana')
    print(' 2. Ask Nahida for help')
    print(' 3. Give up')
    print(f"{'':=^40}")
