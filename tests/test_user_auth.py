import unittest
from pathlib import Path

from user_auth import UserAuth
from db_conn import SQLite



DB_PATH = Path("enpasman.db")


class TestUserAuth(unittest.TestCase):
    
    def setUp(self):
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
        print('Users tear down complete')
        
if __name__ == "__main__":
    unittest.main()
