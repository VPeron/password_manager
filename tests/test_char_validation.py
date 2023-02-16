import unittest

from utils.char_validation import validate_lentgh, sanitize, has_min_requirements, generate_password



class TestRefactorEncryption(unittest.TestCase):
    def setUp(self):
        self.test_letter = 'qwertz'
        self.test_aplhanum = 'qwertz1234'
        self.test_alphanum_spec = 'qwertz123$'
        self.test_invalid_chars = 'qwe1$"§'
        self.test_cases = [self.test_letter, self.test_aplhanum, self.test_alphanum_spec, self.test_invalid_chars]
    
    def test_validate_lentgh(self):
        lenght_cases = [validate_lentgh(case) for case in self.test_cases]
        self.assertEqual(all(lenght_cases), True)
        pass_lenght_cases = [validate_lentgh(case, inp_type='password') for case in self.test_cases]
        self.assertEqual(all(pass_lenght_cases), False)
    
    def test_sanitize(self):
        invalid_char_cases = [sanitize(case) for case in self.test_cases]
        self.assertEqual(all(invalid_char_cases), False)
        valid_char_cases = [sanitize(case) for case in self.test_cases[:-1]]
        self.assertEqual(all(valid_char_cases), True)
    
    def test_has_min_requirements(self):
        test_cases = [has_min_requirements(case) for case in self.test_cases]
        self.assertEqual(all(test_cases), False)
        self.assertEqual(has_min_requirements(self.test_letter), False)
        self.assertEqual(has_min_requirements(self.test_aplhanum), False)
        self.assertEqual(has_min_requirements(self.test_alphanum_spec), True)
        self.assertEqual(has_min_requirements(self.test_invalid_chars), True)
    
    def test_generate_password(self):
        new_password = generate_password()
        self.assertIsInstance(new_password, str)
        self.assertEqual(len(new_password), 12)
        another_password = generate_password(16)
        self.assertIsInstance(another_password, str)
        self.assertEqual(len(another_password), 16)

if __name__ == "__main__":
    unittest.main()   
