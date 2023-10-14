import secrets
import string
import re

from utils.get_config import fetch_config

SPECIAL_CHARACTERS = fetch_config(["special_chars"])["special_chars"]


def char_pool():
    # create char pool
    letters_upper = string.ascii_uppercase
    letters_lower = string.ascii_lowercase
    digits = string.digits
    special_chars = SPECIAL_CHARACTERS
    available_chars = letters_upper + letters_lower + digits + special_chars
    return available_chars


# function to sanitize input against XSS and SQL injection attacks
# most special characters have been removed from SPECIAL_CHARACTERS
def hard_sanitize(input_string: str):
    """
    this may not be used for passwords as the input string may be
    modified thus misleading the user
    """
    # remove any HTML or JavaScript tags
    sanitized_string = re.sub(r"<.*?>", "", input_string)
    # escape any single quotes to prevent SQL injection attacks
    sanitized_string = sanitized_string.replace("'", "''")
    return sanitized_string


def validate_lentgh(data: str, inp_type="data"):
    if inp_type == "data":
        if len(data) >= 3 and len(data) <= 64:
            return True
    elif inp_type == "password":
        if len(data) >= 8 and len(data) <= 64:
            return True
    return False


def sanitize(data: str):
    # check if all input chars are valid
    available_chars = char_pool()
    failed_chars = [char for char in data if char not in available_chars]
    if len(failed_chars) == 0 and validate_lentgh(data):
        return True
    else:
        return False


def has_min_requirements(data: str):
    # return True if data contains at least 1 letter, 1 digit and 1 special character
    digit = True
    alpha = True
    special_char = False
    if not any(c.isdigit() for c in data):
        digit = False
    if not any(c.isalpha() for c in data):
        alpha = False
    spec_char_list = [char for char in data if char in SPECIAL_CHARACTERS]
    if len(spec_char_list) > 0:
        special_char = True
    return all([digit, alpha, special_char])


def generate_password(n: int = 12):
    # generate a n-char long password that meet certain criteria
    available_chars = char_pool()
    # generate random sequence of chars from pool
    password_chars = [(secrets.choice(available_chars)) for _ in range(n)]
    password = "".join(password_chars)
    # check if at least one char is digit, upper and lower case
    conditions = [has_min_requirements(password), sanitize(password)]
    if all(conditions):
        return password
    else:
        return generate_password(n)
