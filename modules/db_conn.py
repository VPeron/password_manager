from pathlib import Path
import sqlite3

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
        

def setup_db_tables():
    # separate function to setup tables
    # setup first use - refactor with packaging
    # create users table if it doesnt exits
    pre_query_users = '''CREATE TABLE IF NOT EXISTS users
                (user_id INTEGER PRIMARY KEY, 
                username text UNIQUE, 
                password BLOB, 
                salt_token BLOB)'''
    # create accounts table if it doesnt exits
    pre_query_accounts = '''CREATE TABLE IF NOT EXISTS accounts
            (id INTEGER PRIMARY KEY, 
            url text, 
            hashedpass BLOB,
            account_name text,
            user_id INTEGER,
            FOREIGN KEY (user_id) 
                REFERENCES users (user_id)
                ON DELETE CASCADE)'''

    with SQLite(DB_PATH) as db:
        db.cursor.execute(pre_query_users)
        db.cursor.execute(pre_query_accounts)
        db.connection.commit()
