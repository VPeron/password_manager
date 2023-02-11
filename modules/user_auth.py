import hashlib
import os

from modules.db_conn import SQLite, DB_PATH
from modules.password_generator import sanitize


class UserAuth:
    def __init__(self, username, password) -> None:
        self.username = username
        self.password = password.encode()
    
    def validate_credentials(self):
        # validate credentials criteria
        if 3 < len(self.username) < 16 and 7 < len(self.password) < 64:
            return True
        return False

    def register(self):
        if not self.validate_credentials():
            print('Username must be at least 4 characters long.\nPasswords must be at least 8 characters long.')
            print('Try again')
            return
        else:
            print('valid cred lentgh')
        # check if username is unique
        username_query = """SELECT username FROM users where username = ?"""
        with SQLite(DB_PATH) as db:
            db.cursor.execute(username_query, (self.username,))
            result = db.cursor.fetchone()
        if not result:
            # username is unique in db so we persist it
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
            return
 
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
