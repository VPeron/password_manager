import hashlib
from pathlib import Path
import os

from db_conn import SQLite



DB_PATH = Path("enpasman.db")

# setup first use - refactor with packaging
# create users table if it doesnt exits
pre_query_users = '''CREATE TABLE IF NOT EXISTS users
            (user_id INTEGER PRIMARY KEY, username text UNIQUE, password BLOB, salt_token BLOB)'''
# create accounts table if it doesnt exits
pre_query_accounts = '''CREATE TABLE IF NOT EXISTS accounts
        (id INTEGER PRIMARY KEY, 
        url text UNIQUE, 
        hashedpass BLOB,
        account_name text UNIQUE,
        user_id INTEGER,
        FOREIGN KEY (user_id) 
            REFERENCES users (user_id)
            ON DELETE CASCADE)'''
with SQLite(DB_PATH) as db:
    db.cursor.execute(pre_query_users)
    db.cursor.execute(pre_query_accounts)
    db.connection.commit()

class UserAuth:
    def __init__(self, username, password) -> None:
        self.username = username
        self.password = password.encode()
        

    def register(self):
        # check if username is unique
        #TODO first run will break as users table does not exist yet
        username_query = """SELECT username FROM users where username = ?"""
        with SQLite(DB_PATH) as db:
            db.cursor.execute(username_query, (self.username,))
            result = db.cursor.fetchone()
        if not result:
            # username is unique in db
            self.salt_token = os.urandom(16)
            query = "INSERT INTO users (username, password, salt_token) VALUES (?,?,?)"
            # custom db connection context manager
            with SQLite(DB_PATH) as db:
                # hash password
                password_hash = hashlib.sha256(self.password).hexdigest()
                # add username and hash_password to db
                db.cursor.execute(query, (self.username, password_hash, self.salt_token))
                db.connection.commit()
        else:
            print('try a different username')
            exit()
 
    def login(self):
        query = "SELECT password, user_id FROM users WHERE username = ?"
        with SQLite(DB_PATH) as db:
            db.cursor.execute(query, (self.username,))
            try:
                (correct_password_hash, self.user_id) = db.cursor.fetchone()
            except TypeError:
                print('invalid username or password')
                correct_password_hash = False
        if correct_password_hash:
            password_hash = hashlib.sha256(self.password).hexdigest()
            if password_hash == correct_password_hash:
                return True
            else:
                print('invalid username or password')
        return False
    
    def get_salt_token(self):
        query = "SELECT salt_token FROM users WHERE user_id = ?"
        with SQLite(DB_PATH) as db:
            db.cursor.execute(query, (self.user_id,))
            salt_token = db.cursor.fetchone()
        return salt_token[0]