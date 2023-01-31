import argparse
from getpass import getpass
import base64

from prettytable import PrettyTable
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

from user_auth import UserAuth
from accounts_handler import PassSession



# Cryptography helper functions
def encrypt_data(data:str, password:bytes, salt_token:bytes):
    # Derive encryption key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt_token,
        iterations=300000,
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
        iterations=300000,
        backend=default_backend()
    )
    encryption_key = base64.urlsafe_b64encode(kdf.derive(password))
    # Decrypt data using Fernet
    cipher = Fernet(encryption_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode()

def display_entry(entries:list):
    # display all matching entries as a table
    display_table = PrettyTable(['Url', 'Password', 'Account Name'])
    display_table.add_row(entries)
    print(display_table)

def main():
    main_session = PassSession(user_session.username, user_session.user_id)
    # get user salt
    salt_token = user_session.get_salt_token()
    print(f"\nHi {user_session.username.capitalize()}!\n")
    # retrieve user existing account names
    # get_all_account_names() triggers self.accounts to be created
    main_session.get_all_account_names()
    # session_accounts will help ensure unique account names
    session_accounts = list(main_session.accounts.values())
    print('Saved accounts')
    print(main_session.accounts)

    while True:
        #TODO sanitize all inputs before querying sql
        menu = input("[V]iew\n[A]dd\n[e]dit\n[D]elete\n[Q]uit\n-> ")
        # View
        if menu.lower() == "v":
            account_name = input("Account Name: ")
            try:
                results = main_session.view_entry(account_name)
                if len(results) == 0:
                    print('No entries found')
                    continue
                # collect entry to be dsplayed
                url, hashed_pass, fetched_account_name = results
                decrypted_pass = decrypt_data(hashed_pass.encode(), user_session.password, salt_token)
                
                display_entry((url, decrypted_pass, fetched_account_name))
            except TypeError:
                print('Account name not found.')  
        # Add
        elif menu.lower() == "a":
            new_url = input('Url: ')
            new_password = getpass('Password: ').encode()
            new_account_name = input('Account Name: ')
            # enforce unique account names
            if new_account_name in session_accounts:
                print('This Account name already exists')
                continue
            encrypted_password = encrypt_data(new_password, user_session.password, salt_token)
            main_session.add_entry(new_url, encrypted_password.decode(), new_account_name)
            # update sessions accounts* - more elegant way?
            session_accounts.append(new_account_name)
            print('New Entry Created.')
        # Edit
        elif menu.lower() == "e":
            account_name = input('Account Name to edit: ')
            if account_name in session_accounts:
                encrypted_password = encrypt_data(getpass('New Password: ').encode(), user_session.password, salt_token)
                main_session.edit_entry(encrypted_password.decode(), account_name)
                print('Edit Completed.')
            else:
                print('Account name not found.')
        # Delete
        elif menu.lower() == "d":
            main_session.delete_entry(input("Account Name: "))
            print('Account Deleted.')
        # Quit
        elif menu.lower() == "q":
            print("Goodbye")
            break
        else:
            print("Invalid Option")
            continue

if __name__ == '__main__':
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
    user_session = UserAuth(input('Username: '), getpass('Password: '))
    if args.register != None: 
        user_session.register()
    elif args.login != None:
        if user_session.login():
            main()    
