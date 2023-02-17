import argparse
import os
from pathlib import Path
import sqlite3
from getpass import getpass
import logging

import pyperclip

from utils.encryption import encrypt_data, decrypt_data
from utils.char_validation import sanitize, generate_password
from utils.ascii_art import get_ascii_art
from utils.display_frame import frame


logging.basicConfig(
    filename="pass_man_logger.log", format="%(asctime)s %(message)s", level=logging.INFO
)
DB_PATH = Path("passwordmanager.db")


class SQLite:
    """
    A minimal sqlite3 context manager to remove some
    boilerplate code from the application level.
    """

    def __init__(self, path: Path):
        self.path = path

    def __enter__(self):
        self.connection: sqlite3.Connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.cursor: sqlite3.Cursor = self.connection.cursor()
        # return methods of the context handler
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.connection.close()


class UserAuth(SQLite):
    """
    user registration and authentication
    """
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(path)
        if not os.path.exists(path):
            self.setup_db_tables()
            logging.info("tables setup")

    def setup_db_tables(self):
        # setup db, setup tables
        # create users table if it doesnt exits
        pre_query_users = """CREATE TABLE IF NOT EXISTS users
                    (user_id INTEGER PRIMARY KEY, 
                    username text UNIQUE, 
                    password BLOB, 
                    salt_token BLOB)"""
        # create accounts table if it doesnt exits
        pre_query_accounts = """CREATE TABLE IF NOT EXISTS accounts
                (id INTEGER PRIMARY KEY, 
                url text, 
                hashedpass BLOB,
                account_name text,
                user_id INTEGER,
                FOREIGN KEY (user_id) 
                    REFERENCES users (user_id)
                    ON DELETE CASCADE)"""
        with SQLite(self.path) as db:
            db.cursor.execute(pre_query_users)
            db.cursor.execute(pre_query_accounts)
            db.connection.commit()

    def register(self, username, password):
        # check if all characters are valid in user input
        if not all([sanitize(username), sanitize(password)]):
            print("\nOnly some special characters are allowed")
            print("Registration failed. Try again")
            logging.info(f'failed registration: {username}')
            return False
        # check if username is unique
        username_query = """SELECT username FROM users where username = ?"""
        with SQLite(self.path) as db:
            db.cursor.execute(username_query, (username,))
            result = db.cursor.fetchone()
        if not result:
            # username is unique in db so we persist it
            self.master_key = username + password
            salt_token = os.urandom(16)
            query = "INSERT INTO users (username, password, salt_token) VALUES (?,?,?)"
            # custom db connection context manager
            with SQLite(self.path) as db:
                # add username and password to db
                password = encrypt_data(
                    password.encode(), self.master_key.encode(), salt_token
                )
                db.cursor.execute(query, (username, password, salt_token))
                db.connection.commit()
                logging.info(f"registration: {username}")
                return True
        else:
            print("try a different username")
            return False

    def login(self, username, password):
        # check if all characters are valid in user input
        if not all([sanitize(username), sanitize(password)]):
            print("invalid login username or password")
            return False, {"message": "invalid username or password"}
        self.master_key = username + password
        query = "SELECT password, user_id, salt_token FROM users WHERE username = ?"
        with SQLite(DB_PATH) as db:
            db.cursor.execute(query, (username,))
            try:
                (correct_password_hash, user_id, salt_token) = db.cursor.fetchone()
            except TypeError:
                print("invalid username or password")
                correct_password_hash = False
        if correct_password_hash:
            decrypt_password_hash = decrypt_data(
                correct_password_hash, self.master_key.encode(), salt_token
            )
            if password == decrypt_password_hash:
                logging.info(f"login: {username}")
                return True, {
                    "username": username,
                    "master_key": self.master_key.encode(),
                    "user_id": user_id,
                    "salt_token": salt_token,
                }
            else:
                print("invalid username or password")
        return False, {"message": "invalid username or password"}


class AccountManager(UserAuth):
    """
    handles account operations and general authorization system for a user session
    """
    
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(path)

    def add_entry(self, url, hashed_pass, account_name, user_id):
        # check if all characters are valid in user input
        if all([sanitize(url), sanitize(account_name)]):
            # add entry to the database
            add_query = "INSERT INTO accounts (url, hashedpass, account_name, user_id) VALUES (?,?,?,?)"
            with SQLite(self.path) as db:
                db.cursor.execute(add_query, (url, hashed_pass, account_name, user_id))
                db.connection.commit()
            # update accounts
            self.get_all_account_names(user_id)
            logging.info(f"add_entry: {user_id}")
        else:
            print("invalid lenght or characters. Try again")
            return False

    def view_entry(self, account_name, user_id):
        # fetch account_name & password by account name & user_id
        view_query = "SELECT url, hashedpass, account_name FROM accounts WHERE account_name = ? AND user_id = ?"
        with SQLite(self.path) as db:
            db.cursor.execute(view_query, (account_name, user_id))
            return db.cursor.fetchone()

    def edit_entry(self, new_hashedpass, account_name, user_id):
        # check if all characters are valid in user input
        if sanitize(account_name):
            # edit entry
            confirm = input("Confirm Edit: (Y/n): ")
            if confirm == "Y":
                edit_query = "UPDATE accounts SET hashedpass = ? WHERE account_name = ? AND user_id = ?"
                with SQLite(self.path) as db:
                    db.cursor.execute(
                        edit_query, (new_hashedpass, account_name, user_id)
                    )
                    db.connection.commit()
            self.get_all_account_names(user_id)
            logging.info(f"edit_entry: {user_id}")
        else:
            print("invalid lenght or characters. Try again")
            return

    def delete_entry(self, account_name, user_id):
        # check if all characters are valid in user input
        if sanitize(account_name):
            # delete entry
            confirm = input("Delete Entry (Y/n): ")
            if confirm == "Y":
                delete_query = (
                    "DELETE from accounts WHERE account_name = ? AND user_id = ?"
                )
                with SQLite(self.path) as db:
                    db.cursor.execute(delete_query, (account_name, user_id))
                    db.connection.commit()
            # update accounts
            self.get_all_account_names(user_id)
            logging.info(f"del_entry: {user_id}")
        else:
            print("invalid lenght or characters. Try again")
            return

    def get_all_account_names(self, user_id):
        # fetch all account names
        query = "SELECT url, account_name FROM accounts WHERE user_id = ?"
        with SQLite(self.path) as db:
            db.cursor.execute(query, (user_id,))
            accounts = db.cursor.fetchall()
        self.accounts = {}
        for item in accounts:
            self.accounts[item[0]] = item[1]
        return self.accounts


########################################################################


def main(user: dict):
    # init accounts handler
    test_session = AccountManager(test_session.path)
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
            test_session.add_entry(url, password, account_name, user["user_id"])
        # VIEW
        if menu.lower() == "v":
            account_name = input("Account Name: ")
            if account_name in test_session.accounts.values():
                result = test_session.view_entry(account_name, user["user_id"])
                if result:
                    decrypted_pass = decrypt_data(
                        result[1], user["master_key"], user["salt_token"]
                    )
                    frame(['Url', 'Password', 'Account Name'], [result[0], 'copied to clipboard', result[2]])
                    pyperclip.copy(decrypted_pass)
                    pyperclip.paste()
                    logging.info('pass request')
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
