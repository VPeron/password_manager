import random
import string



def char_pool():
    # char pool
    letters_upper = string.ascii_uppercase
    letters_lower = string.ascii_lowercase
    digits = string.digits
    special_chars = '!$%&/()?{[]}*'
    available_chars = letters_upper + letters_lower + digits + special_chars
    return available_chars

def generate_password(n:int):
    # generate a n-char long password that meet certain criteria
    available_chars = char_pool()
    # generate random sequence of chars from pool
    password_chars = [(random.choice(available_chars)) for _ in range(n)]
    password = ''.join(password_chars)
    # check if at least one char is digit, upper and lower case
    conditions = [
        any(map(str.isdigit, password)), 
        any(map(str.isupper, password)), 
        any(map(str.islower, password)),
        ]
    if all(conditions):
        return password
    else:
        return generate_password(n)
