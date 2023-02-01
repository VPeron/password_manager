import unittest
from user_auth import UserAuth
from accounts_handler import PassSession



class testPassSession(unittest.TestCase):
    
    def setUp(self) -> None:
        self.test_user = UserAuth('test_user3', 'test_pass3')
        self.test_user.register()
        self.test_user.login()
        self.test_session = PassSession(self.test_user.username, self.test_user.user_id)
        self.test_session.get_all_account_names()
    
    def test_get_all_account_names(self):
        self.assertIsInstance(self.test_session.accounts, dict)
        
if __name__ == "__main__":
    unittest.main()