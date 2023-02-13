import string
import secrets



SPECIAL_CHARACTERS = '!$%&/()?{[]}*'

def char_pool():
    # char pool
    letters_upper = string.ascii_uppercase
    letters_lower = string.ascii_lowercase
    digits = string.digits
    special_chars = SPECIAL_CHARACTERS
    available_chars = letters_upper + letters_lower + digits + special_chars
    return available_chars

def sanitize(data:str):
    # check if all characters are valid
    available_chars = char_pool()
    failed_chars = [char for char in data if char not in available_chars]
    if len(failed_chars) == 0:
        return True, failed_chars
    else:
        return False, failed_chars

def has_min_requirements(data:str):
    # return True if the string contains at least 1 letter, 1 digit and 1 special character
    digit = True
    alpha = True
    special_char = False
    special_chars_counter = 0
    if not any(c.isdigit() for c in data):
        digit = False
    if not any(c.isalpha() for c in data):
        alpha = False
    for char in data:
        if char in SPECIAL_CHARACTERS:
            special_chars_counter += 1
    if special_chars_counter > 0:
        special_char = True
    return all([digit, alpha, special_char])

def generate_password(n:int):
    # generate a n-char long password that meet certain criteria
    available_chars = char_pool()
    # generate random sequence of chars from pool
    password_chars = [(secrets.choice(available_chars)) for _ in range(n)]
    password = ''.join(password_chars)
    # check if at least one char is digit, upper and lower case
    conditions = [
        has_min_requirements(password),
        sanitize(password)[0]
        ]
    if all(conditions):
        return password
    else:
        return generate_password(n)
