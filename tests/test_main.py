import unittest

from main import encrypt_data, decrypt_data



class testMain(unittest.TestCase):
    def setUp(self):
        self.data = b'test string'
        self.password = b'test password'
        self.salt = b'test salt'
    
    def test_encrypt_data(self):
        self.encrypted_data = encrypt_data(self.data, self.password, self.salt)
        self.assertIsInstance(self.encrypted_data, bytes)
    
    def test_decrypt_data(self):
        self.encrypted_data = encrypt_data(self.data, self.password, self.salt)
        self.plain_text_data = decrypt_data(self.encrypted_data, self.password, self.salt)
        self.assertIsInstance(self.plain_text_data, str)
        self.assertEqual(self.plain_text_data, self.data.decode())
        
if __name__ == "__main__":
    unittest.main()