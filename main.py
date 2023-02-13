import argparse
from getpass import getpass
import base64
import os
import logging

from prettytable import PrettyTable
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import pyperclip

from modules.db_conn import DB_PATH, setup_db_tables
from modules.user_auth import UserAuth
from modules.accounts_handler import PassSession
from modules.ascii_art import get_ascii_art
from modules.password_generator import generate_password



logging.basicConfig(filename='pass_man_logger.log', format='%(asctime)s %(message)s', level=logging.INFO)
SHA_ITERS = 480_000

def encrypt_data(data:bytes, password:bytes, salt_token:bytes):
    # Derive encryption key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt_token,
        iterations=SHA_ITERS,
        backend=default_backend()
    )
    encryption_key = base64.urlsafe_b64encode(kdf.derive(password))
    # Encrypt data using Fernet
    cipher = Fernet(encryption_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

def decrypt_data(encrypted_data:bytes, password:bytes, salt_token:bytes):
    # Derive encryption key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt_token,
        iterations=SHA_ITERS,
        backend=default_backend()
    )
    encryption_key = base64.urlsafe_b64encode(kdf.derive(password))
    # Decrypt data using Fernet
    cipher = Fernet(encryption_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode()

def display_entry(columns:list, entries):
    # display entries as a table
    display_table = PrettyTable(columns)
    if isinstance(entries[0], list):
        display_table.add_rows(entries)
    else:
        display_table.add_row(entries)
    print(display_table)

def main():
    # init and prep user session
    main_session = PassSession(user_session.username, user_session.user_id)
    # get user salt -> #TODO move to account level
    salt_token = user_session.get_salt_token()
    print('\nLogin Successful\nUser Accounts loaded')
    print(f"\nUser Session: {user_session.username}\n")
    # retrieve user existing account names
    # get_all_account_names() triggers self.accounts to be created or updated
    main_session.get_all_account_names()
    logging.info(f"Login User: {user_session.username}")

    while True:
        input('Press Enter to Continue:\n')
        os.system('clear')
        main_session.get_all_account_names()
        print(f'User: {user_session.username}')
        print('Saved accounts:')
        print(list(main_session.accounts.values()))
        menu = input("\n[V]iew\n[A]dd\n[e]dit\n[D]elete\n[Q]uit\n-> ")
        # View
        if menu.lower() == "v":
            account_name = input("Account Name: ")
            try:
                results = main_session.view_entry(account_name)
                if len(results) == 0:
                    print('No entries found')
                    continue
                url, hashed_pass, fetched_account_name = results
                # fetch plain text password
                decrypted_pass = decrypt_data(hashed_pass.encode(), user_session.password, salt_token)
                display_entry(['url', 'Password', 'Account'], (url, 'copied to clipboard', fetched_account_name))
                pyperclip.copy(decrypted_pass)
                pyperclip.paste()
            except TypeError:
                print('Account name not found.')
            
        # Add
        elif menu.lower() == "a":
            new_url = input('Url: ')
            new_password = getpass('Password (Leave blank to auto-generate): ').encode()
            if len(new_password) == 0:
                # generate random password default lentgh = 12
                new_password = generate_password(12).encode()
            new_account_name = input('Account Name: ')
            # enforce unique account names
            if new_account_name in list(main_session.accounts.values()):
                print('This Account name already exists')
                continue
            encrypted_password = encrypt_data(new_password, user_session.password, salt_token)
            main_session.add_entry(new_url, encrypted_password.decode(), new_account_name)
            print('\nNew Entry Created.')
            display_entry(['url', 'Account'], [new_url, new_account_name])
            logging.info("New Account created")
        # Edit
        elif menu.lower() == "e":
            account_name = input('Account Name to edit: ')
            if account_name in list(main_session.accounts.values()):
                new_password = getpass('New Password (Leave blank to auto-generate): ').encode()
                if len(new_password) == 0:
                    # generate random password default lentgh = 12
                    new_password = generate_password(12).encode()
                encrypted_password = encrypt_data(new_password, user_session.password, salt_token)
                main_session.edit_entry(encrypted_password.decode(), account_name)
                print('Edit Completed.')
            else:
                print('Account name not found')
            logging.info("Account Edit")
        # Delete
        elif menu.lower() == "d":
            del_account = input("Account Name: ")
            if del_account in list(main_session.accounts.values()):
                main_session.delete_entry(del_account)
                print('Account Deleted.')
            else:
                print(f'Account {del_account} not found')
            logging.info("Account Delete")
        # Quit
        elif menu.lower() == "q":
            print("\n  Goodbye\n")
            break
        else:
            print("invalid option")
            continue

if __name__ == '__main__':
    try:
        if not os.path.exists(DB_PATH):
            # setup sqlite3 database and tables first time use or reset
            setup_db_tables(DB_PATH)
    except Exception as e:
        print(f"An error occurred: {e}")
    # instanciate parser object
    parser = argparse.ArgumentParser(description = "A Password Manager.")
    # define a register and login arguments for parser object
    parser.add_argument("-r", "--register", type = str, nargs = '*',
                        metavar = "str", default = None,
                        help = "Register a user for the Password Manager.")
    parser.add_argument("-l", "--login", type = str, nargs = '*',
                        metavar = "str", default = None,
                        help = "Login to the Password Manager.")
    # parse the arguments from standard input
    args = parser.parse_args()
    os.system('clear')
    get_ascii_art()
    user_session = UserAuth(input('Username: '), getpass('Password: '))
    if args.register != None: 
        user_session.register()
        logging.info(f"New User Registration: {user_session.username}")
    elif args.login != None:
        if user_session.login():
            main()    
