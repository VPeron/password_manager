import unittest
from user_auth import UserAuth


class TestUserAuth(unittest.TestCase):
    
    def setUp(self):
        self.test_user = UserAuth('test_user5', 'test_pass')
        self.test_user.register()
        self.test_user.login()
        print('Setup complete')
    
    def test_get_salt_token(self):
        salt_token = self.test_user.get_salt_token()
        self.assertIsInstance(salt_token, bytes)
        
    def tearDown(self):
        print('tearing down')
        
if __name__ == "__main__":
    unittest.main()
    
    #TODO test unique username error
    #TODO test salt encoding
    #TODO setup tests database
    #TODO setup teardown