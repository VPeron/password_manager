from pathlib import Path

from db_conn import SQLite



DB_PATH = Path("enpasman.db")

class PassSession:
    # handles operations and general AUTH system for a user session
    def __init__(self, user_session, user_id) -> None:
        self.user_session = user_session
        self.user_id = user_id
        
    def add_entry(self, url, hashed_pass, account_name):
        # add entry to the database
        #TODO sanitize sql input
        add_query = "INSERT INTO accounts (url, hashedpass, account_name, user_id) VALUES (?,?,?,?)"
        with SQLite(DB_PATH) as db:
            db.cursor.execute(add_query, (url, hashed_pass, account_name, self.user_id))
            db.connection.commit()
    
    def view_entry(self, account_name):
        # fetch account_name & password by account name & user_id
        #TODO sanitize sql input
        view_query = "SELECT url, hashedpass, account_name FROM accounts WHERE account_name = ? AND user_id = ?"
        with SQLite(DB_PATH) as db:
            db.cursor.execute(view_query, (account_name, self.user_id))
            return db.cursor.fetchone()
    
    def edit_entry(self, new_hashedpass, account_name):
        # edit entry
        #TODO sanitize sql input
        confirm = input('Confirm Edit: (Y/n): ')
        if confirm == 'Y':
            edit_query = "UPDATE accounts SET hashedpass = ? WHERE account_name = ? AND user_id = ?"
            with SQLite(DB_PATH) as db:
                db.cursor.execute(edit_query, (new_hashedpass, account_name, self.user_id))
                db.connection.commit()
    
    def delete_entry(self, account_name):
        # delete entry
        #TODO sanitize sql input
        confirm = input('Delete Entry (Y/n): ')
        if confirm == 'Y':
            delete_query = "DELETE from accounts WHERE account_name = ? AND user_id = ?"
            with SQLite(DB_PATH) as db:
                db.cursor.execute(delete_query, (account_name, self.user_id))
                db.connection.commit()

    def get_all_account_names(self):
        # fetch all account names
        query = "SELECT url, account_name FROM accounts WHERE user_id = ?"
        with SQLite(DB_PATH) as db:
            db.cursor.execute(query, (self.user_id,))
            self.accounts = db.cursor.fetchall()
