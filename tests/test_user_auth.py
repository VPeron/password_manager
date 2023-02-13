import unittest
from pathlib import Path
import os

from modules.user_auth import UserAuth
from modules.password_generator import sanitize
from modules.db_conn import SQLite, setup_db_tables



DB_PATH = Path("tests/tests_db.db")


class TestUserAuth(unittest.TestCase):
    
    def setUp(self):
        setup_db_tables(DB_PATH)
        self.test_user = UserAuth('test_user', 'test_pass')
        self.test_user.register()
        self.test_user.login()
        print('Users setup complete')
    
    def test_get_salt_token(self):
        salt_token = self.test_user.get_salt_token()
        self.assertIsInstance(salt_token, bytes)
 
    def tearDown(self):
        user_query = "DELETE FROM users WHERE username = 'test_user'"
        
        with SQLite(DB_PATH) as db:
            db.cursor.execute(user_query)
            db.connection.commit()
        try:
            os.remove(DB_PATH)
        except OSError as e:
            print('Error found: ', e)
        print('Users tear down complete')
        
if __name__ == "__main__":
    unittest.main()
