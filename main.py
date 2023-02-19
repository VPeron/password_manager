import argparse
import os
from pathlib import Path
from getpass import getpass
import logging

import pyperclip

from utils.encryption import encrypt_data, decrypt_data
from utils.char_validation import generate_password
from utils.ascii_art import get_ascii_art
from utils.display_frame import frame
from modules.class_modules import AccountManager, UserAuth


logging.basicConfig(
    filename="pass_man_logger.log", format="%(asctime)s %(message)s", level=logging.INFO
)
DB_PATH = Path("passwordmanager.db")


def main(user: dict):
    # init accounts handler
    test_session = AccountManager(DB_PATH)
    print(f'\nLogin Successfull\nHi {user["username"]}\n')
    # init menu loop
    while True:
        input("\nPress Enter To Continue ")
        os.system("clear")
        print(f'User: {user["username"]}')
        test_session.get_all_account_names(user["user_id"])
        print("###        Accounts       ###")
        try:
            frame(['url', 'account name'], [[k, v] for k, v in test_session.accounts.items()])
        except IndexError:
            print('Your accounts will be displayed here')
        # MENU
        menu = input("\n- Menu -\n(a)dd\n(v)iew\n(e)dit\n(d)elete\n(q)uit\n -> ")
        # ADD
        if menu.lower() == "a":
            url = input("Url: ")
            new_password = getpass("Password (leave blank to auto-generate): ")
            if len(new_password) == 0:
                # generate an n-char-long password (n=12)
                new_password = generate_password()
            password = encrypt_data(
                new_password.encode(), user["master_key"], user["salt_token"]
            )
            account_name = input("Account Name: ")
            if account_name in test_session.accounts.values():
                print('This account name already exists')
                continue
            else:
                test_session.add_entry(url, password, account_name, user["user_id"])
        # VIEW
        if menu.lower() == "v":
            account_name = input("Account Name: ")
            if account_name in test_session.accounts.values():
                result = test_session.view_entry(account_name, user["user_id"])
                if result:
                    decrypted_pass = decrypt_data(
                        result[2], user["master_key"], user["salt_token"]
                    )
                    frame(['Id', 'Url', 'Password', 'Account Name'], [result[0], result[1], 'copied to clipboard', result[3]])
                    pyperclip.copy(decrypted_pass)
                    pyperclip.paste()
                    logging.info('password request')
            else:
                print("account not found")
        # EDIT
        if menu.lower() == "e":
            account_name = input("Account Name: ")
            # ensure account exists
            if account_name not in test_session.accounts.values():
                print("account not found")
                continue
            new_password = getpass("Password (leave blank to auto-generate): ")
            if len(new_password) == 0:
                # generate an n-char-long password (n=12)
                new_password = generate_password()
            enc_password = encrypt_data(
                new_password.encode(), user["master_key"], user["salt_token"]
            )
            test_session.edit_entry(enc_password, account_name, user["user_id"])
        # DELETE
        if menu.lower() == "d":
            account_name = input("Account Name: ")
            # ensure account exists
            if account_name in test_session.accounts.values():
                test_session.delete_entry(account_name, user["user_id"])
            else:
                print("account not found")
        # QUIT
        if menu.lower() == "q":
            print("\n   Bye\n")
            break


if __name__ == "__main__":
    authenticator = UserAuth(DB_PATH)
    # instanciate parser object
    parser = argparse.ArgumentParser(description="A Password Manager.")
    # define a register and login arguments for parser object
    parser.add_argument(
        "-r",
        "--register",
        type=str,
        nargs="*",
        metavar="str",
        default=None,
        help="Register a user for the Password Manager.",
    )
    parser.add_argument(
        "-l",
        "--login",
        type=str,
        nargs="*",
        metavar="str",
        default=None,
        help="Login to the Password Manager.",
    )
    # parse the arguments from standard input
    args = parser.parse_args()
    os.system('clear')
    get_ascii_art()
    if args.register != None:
        # register a new user
        authenticator.register(input("Username: "), getpass("Password: "))

    elif args.login != None:
        # authenticate the user
        user = authenticator.login(input("Username: "), getpass("Password: "))
        if user[0]:
            main(user[1])
        else:
            print("Authentication failed.")
