import argparse
import os
from pathlib import Path
from getpass import getpass

import pyperclip

from utils.encryption import encrypt_data, decrypt_data
from utils.char_validation import generate_password, SPECIAL_CHARACTERS
from utils.ascii_art import get_ascii_art
from utils.display_frame import frame
from modules.dbconn_auth_accounts import UserAuth, AccountManager


DB_PATH = Path("passwordmanager.db")


def main(user: dict):
    """
    TODO: add docs
    """
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
            frame(
                ["url", "account name"],
                [[k, v] for k, v in test_session.accounts.items()],
            )
        except IndexError:
            print("Your accounts will be displayed here")
        # MENU
        menu = input("\n- Menu -\n(a)dd\n(v)iew\n(e)dit\n(d)elete\n(q)uit\n -> ")
        # ADD
        if menu.lower() == "a":
            _add_entry(test_session, user)

        # VIEW
        if menu.lower() == "v":
            _view_entry(test_session, user)

        # EDIT
        if menu.lower() == "e":
            _edit_entry(test_session, user)

        # DELETE
        if menu.lower() == "d":
            _delete_entry(test_session, user)

        # QUIT
        if menu.lower() == "q":
            print("\n   Bye\n")
            break


def _add_entry(session, user):
    url = input("Url: ")
    new_password = getpass("Password (leave blank to auto-generate): ")
    if len(new_password) == 0:
        # generate an n-char-long password (n=12)
        new_password = generate_password()
    password = encrypt_data(
        new_password.encode(), user["master_key"], user["salt_token"]
    )
    account_name = input("Account Name: ")
    if account_name in session.accounts.values():
        print("This account name already exists")
        return
    else:
        if session.add_entry(url, password, account_name, user["user_id"]):
            print("account created")
        else:
            print("invalid lenght or characters. Try again")


def _view_entry(session, user):
    account_name = input("Account Name: ")
    if account_name in session.accounts.values():
        result = session.view_entry(account_name, user["user_id"])
        if result:
            decrypted_pass = decrypt_data(
                result[2], user["master_key"], user["salt_token"]
            )
            frame(
                ["Id", "Url", "Password", "Account Name"],
                [result[0], result[1], "copied to clipboard", result[3]],
            )
            pyperclip.copy(decrypted_pass)
            pyperclip.paste()
    else:
        print("account not found")


def _edit_entry(session, user):
    account_name = input("Account Name: ")
    # ensure account exists
    if account_name not in session.accounts.values():
        print("account not found")
        return
    new_password = getpass("Password (leave blank to auto-generate): ")
    if len(new_password) == 0:
        # generate an n-char-long password (n=12)
        new_password = generate_password()
    enc_password = encrypt_data(
        new_password.encode(), user["master_key"], user["salt_token"]
    )
    session.edit_entry(enc_password, account_name, user["user_id"])
    print("account edit complete")


def _delete_entry(session, user):
    account_name = input("Account Name: ")
    # ensure account exists
    if account_name in session.accounts.values():
        if session.delete_entry(account_name, user["user_id"]):
            print("account deleted")
        else:
            print("invalid lenght or characters. Try again")
    else:
        print("account not found")


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
    os.system("clear")
    get_ascii_art()
    if args.register != None:
        # register a new user
        result = authenticator.register(input("Username: "), getpass("Password: "))
        if result:
            print("registration complete\nuse -l or --login option to login")
        else:
            print("Registration failed")
            print("try using a different username")
            print(
                f"Note: Only some special characters are allowed: {SPECIAL_CHARACTERS}"
            )

    elif args.login != None:
        # authenticate the user
        user = authenticator.login(input("Username: "), getpass("Password: "))
        if user[0]:
            main(user[1])
        else:
            print("invalid login username or password")
            print("authentication failed")
