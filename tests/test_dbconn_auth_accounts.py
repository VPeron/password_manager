import unittest
from pathlib import Path
import os

from modules.dbconn_auth_accounts import UserAuth, AccountManager


TEST_DB_PATH = Path("tests/testpm.db")


class TestMain(unittest.TestCase):
    def setUp(self):
        self.test_user = "test_user"
        self.test_password = "test_password"
        authenticator = UserAuth(TEST_DB_PATH)
        authenticator.register(self.test_user, self.test_password)
        self.auth = authenticator.login(self.test_user, self.test_password)
        if self.auth[0]:
            self.user = self.auth[1]
        self.test_session = AccountManager(TEST_DB_PATH)

    def test_get_all_account_names(self):
        self.test_session.get_all_account_names(self.user["user_id"])
        self.assertIsInstance(self.test_session.accounts, dict)

    def test_register(self):
        # invalid passwords and username characters
        self.test_user_2 = "tes<asd>"
        self.test_password_2 = 'tes1" or 1=1 §'
        authenticator2 = UserAuth(TEST_DB_PATH)
        response = authenticator2.register(self.test_user_2, self.test_password_2)
        self.assertEqual(response, False)

    def test_login(self):
        self.assertIsInstance(self.auth[0], bool)
        self.assertIsInstance(self.user, dict)

    def test_add_entry(self):
        url = "www.test.com"
        user_name = "tester"
        hashed_pass = b"bad hash"
        account_name = "test"
        self.test_session.add_entry(
            url, user_name, hashed_pass, account_name, self.user["user_id"]
        )
        self.assertEqual(len(self.test_session.accounts.values()), 1)

    def tearDown(self):
        # delete test db
        try:
            os.remove(TEST_DB_PATH)
        except OSError as e:
            print("error cleaning up db file: ", e)


if __name__ == "__main__":
    unittest.main()
