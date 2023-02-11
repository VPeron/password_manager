import unittest
from pathlib import Path
import os

from modules.user_auth import UserAuth
from modules.accounts_handler import PassSession
from modules.db_conn import SQLite, setup_db_tables



DB_PATH = Path("tests/tests_db.db")

class testPassSession(unittest.TestCase):
    def setUp(self) -> None:
        setup_db_tables(DB_PATH)
        self.test_user = UserAuth('test_user', 'test_pass')
        self.test_user.register()
        self.test_user.login()
        self.test_session = PassSession(self.test_user.username, self.test_user.user_id)
        self.test_session.get_all_account_names()
        print('test accounts setup done')
    
    def test_add_entry(self):
        self.test_session.add_entry('www.test.com', self.test_user.password, self.test_user.get_salt_token())
        self.assertEqual(len(self.test_session.accounts.keys()), 2)
    
    def test_get_all_account_names(self):
        self.assertIsInstance(self.test_session.accounts, dict)
    
    def tearDown(self):
        query = "DELETE FROM users WHERE username = 'test_user'"
        account_query = "DELETE FROM accounts WHERE url = 'www.test.com'"
        with SQLite(DB_PATH) as db:
            db.cursor.execute(query)
            db.cursor.execute(account_query)
            db.connection.commit()
        try:
            os.remove(DB_PATH)
        except OSError as e:
            print('Error found: ', e)
        print('test accounts tear down complete')
        
if __name__ == "__main__":
    unittest.main()