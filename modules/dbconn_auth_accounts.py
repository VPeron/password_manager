import logging
import os
import sqlite3
from pathlib import Path

from utils.encryption import encrypt_data, decrypt_data
from utils.char_validation import sanitize


logging.basicConfig(
    filename="pass_man_logger.log", format="%(asctime)s %(message)s", level=logging.INFO
)


class SQLite:
    """
    A minimal sqlite3 context manager to remove some
    boilerplate code from the application level.
    """

    def __init__(self, path: Path):
        self.path = path

    def __enter__(self):
        try:
            self.connection: sqlite3.Connection = sqlite3.connect(self.path)
            self.connection.row_factory = sqlite3.Row
            self.cursor: sqlite3.Cursor = self.connection.cursor()
            # return methods of the context handler
            return self
        except Exception as e:
            raise Exception(f"Error connecting to database: {str(e)}")

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.connection.close()
        except Exception as e:
            raise Exception(f"Error closing database: {str(e)}")
        if exc_val:
            raise Exception(f"Error executing query: {str(exc_val)}")


class UserAuth(SQLite):
    """
    user registration and authentication
    """
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(path)
        if not os.path.exists(path):
            self.setup_db_tables()
            logging.info("table setup")

    def setup_db_tables(self):
        # create users table if it doesnt exits
        query_users = """CREATE TABLE IF NOT EXISTS users
                    (user_id INTEGER PRIMARY KEY, 
                    username text UNIQUE, 
                    password BLOB, 
                    salt_token BLOB)"""
        # create accounts table if it doesnt exits
        query_accounts = """CREATE TABLE IF NOT EXISTS accounts
                (id INTEGER PRIMARY KEY, 
                url text, 
                hashedpass BLOB,
                account_name text,
                user_id INTEGER,
                FOREIGN KEY (user_id) 
                    REFERENCES users (user_id)
                    ON DELETE CASCADE)"""
        # setup db and tables
        with SQLite(self.path) as db:
            db.cursor.execute(query_users)
            db.cursor.execute(query_accounts)
            db.connection.commit()

    def register(self, username: str, password: str):
        # check if all characters are valid in user input
        if not all([sanitize(username), sanitize(password)]):
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
            return False

    def login(self, username: str, password: str):
        # check if all characters are valid in user input
        if not all([sanitize(username), sanitize(password)]):
            return False, {"message": "invalid username or password"}
        self.master_key = username + password
        query = "SELECT password, user_id, salt_token FROM users WHERE username = ?"
        with SQLite(self.path) as db:
            db.cursor.execute(query, (username,))
            try:
                (correct_password_hash, user_id, salt_token) = db.cursor.fetchone()
            except TypeError as e:
                print(e, "invalid username or password")
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
                return False, {"message": "invalid username or password"}
        return False, {"message": "invalid username or password"}


class AccountManager(UserAuth):
    """
    handles account operations and general authorization system for a user session
    """
    
    def __init__(self, path: Path) -> None:
        self.path = path
        super().__init__(path)

    def add_entry(self, url: str, hashed_pass: bytes, account_name: str, user_id: int):
        # check if all characters are valid in user input
        if all([sanitize(url), sanitize(account_name)]):
            # add entry to the database
            add_query = "INSERT INTO accounts (url, hashedpass, account_name, user_id) VALUES (?,?,?,?)"
            with SQLite(self.path) as db:
                db.cursor.execute(add_query, (url, hashed_pass, account_name, user_id))
                db.connection.commit()
            # update accounts
            self.get_all_account_names(user_id)
            logging.info(f"create request - userid:{user_id}")
            return True
        else:
            return False

    def view_entry(self, account_name: str, user_id: int):
        # fetch account_name & password by account name & user_id
        view_query = "SELECT id, url, hashedpass, account_name FROM accounts WHERE account_name = ? AND user_id = ?"
        with SQLite(self.path) as db:
            db.cursor.execute(view_query, (account_name, user_id))
            result = db.cursor.fetchone()
            logging.info(f"view request - userid:{user_id} accountid:{result[0]}")
            return result

    def edit_entry(self, new_hashedpass: bytes, account_name: str, user_id: int):
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
            logging.info(f"edit request - userid:{user_id}")
        else:
            print("invalid lenght or characters. Try again")
            return

    def delete_entry(self, account_name: str, user_id: int):
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
            logging.info(f"delete request - userid:{user_id}")
            return True
        else:
            return False

    def get_all_account_names(self, user_id: int):
        # fetch all account names
        query = "SELECT url, account_name FROM accounts WHERE user_id = ?"
        with SQLite(self.path) as db:
            db.cursor.execute(query, (user_id,))
            accounts = db.cursor.fetchall()
        self.accounts = {}
        for item in accounts:
            self.accounts[item[0]] = item[1]
        return self.accounts
