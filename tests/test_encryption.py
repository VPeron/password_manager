import unittest

from utils.encryption import encrypt_data, decrypt_data



class TestEncryption(unittest.TestCase):
    def setUp(self) -> None:
        self.username = 'vini'
        self.password = 'testpassword123'
        self.mod_strtime = '2023-02-14'
        self.salt_token = b'bad salt'
        self.data = b'some random string'
        self.user_master_key = self.username + self.password + self.mod_strtime
    
    def test_encrypt_data(self):
        encrypted_data = encrypt_data(self.data, self.user_master_key.encode(), self.salt_token)
        self.assertIsInstance(encrypted_data, bytes)
        self.assertEqual(len(encrypted_data), 120)
    
    def test_decrypt_data(self):
        encrypted_data = encrypt_data(self.data, self.user_master_key.encode(), self.salt_token)
        decrypted_data = decrypt_data(encrypted_data, self.user_master_key.encode(), self.salt_token)
        self.assertIsInstance(decrypted_data, str)
        self.assertEqual(decrypted_data, self.data.decode())

if __name__ == "__main__":
    unittest.main()
