# Password Manager

- A simple linux cli password manager that supports multiple user accounts.

Disclaimer: This program is for personal entertainment only and is in many ways,
shapes and forms insecure and underperformant. Suggestions and discussions are most
welcome but PRs will likely be declined as the intent is to educate myself.

### FEATURES

- Register and login multiple users
- Uses Python cryptography library to encrypt stored passwords
- Uses SQLite3 database for persistency, maybe this will scale to posgres
- Saves a URL, username, and password for each account
- View, Edit and Delete functionalities

### Requirements

- Python 3.x
- cryptography library
- prettytable library

### Usage

- To register as a user: python3 main.py -r
- To login as a user: python3 main.py -l

Follow the prompt to add, view, update, or delete an account.

### Status:

- The bare minimum functionally is operational.
argparse cli application should be properly implemented - #TODO crosscheck RP format and possible improvements
- The users table, in the database, is setup with hashed* passwords using SHA256.
- In Accounts, the account names and urls are being saved in plain text. Passwords are encrypted with Fernet.
- The encryption and decryption key for the accounts are master-password derived using the same
algorithm from users flow (hash.sha256), however here a salt is implement with the PBKDF2HMAC class still from
the cryptography library.

### Pipelined implementations:

##TODO improve tests and add logs

##TODO replace plain text password to clipboard paste

##TODO prep for packaging, package

##TODO track passwords age

##TODO implement periodic back up of database file

##TODO improve password generator

##TODO implement a salt per account password rather than user salt_token to derive account password

#### Tests

#TODO setup tests database

### Snowball in Hell and Current Issues:

- sanitize sql queries properly

## Rerences

- ascii art script: https://github.com/kiteco/python-youtube-code/blob/master/ascii/ascii_convert.py
