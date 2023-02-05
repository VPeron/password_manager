import unittest
from pathlib import Path

from user_auth import UserAuth
from accounts_handler import PassSession
from db_conn import SQLite



DB_PATH = Path("enpasman.db")

class testPassSession(unittest.TestCase):
    
    def setUp(self) -> None:
        self.test_user = UserAuth('test_user', 'test_pass')
        self.test_user.register()
        self.test_user.login()
        self.test_session = PassSession(self.test_user.username, self.test_user.user_id)
        self.test_session.get_all_account_names()
        print('test accounts setup done')
    
    def test_add_entry(self):
        self.test_session.add_entry('www.test.com', self.test_user.password, self.test_user.salt_token)
        self.assertEqual(len(self.test_session.accounts), 1)
    
    def test_get_all_account_names(self):
        self.assertIsInstance(self.test_session.accounts, dict)
    
    def tearDown(self):
        query = "DELETE FROM users WHERE username = 'test_user'"
        account_query = "DELETE FROM accounts WHERE url = 'www.test.com'"
        with SQLite(DB_PATH) as db:
            db.cursor.execute(query)
            db.cursor.execute(account_query)
            db.connection.commit()
        print('test accounts tear down complete')
        
if __name__ == "__main__":
    unittest.main()