# Password Manager

Disclaimer: This program is for personal entertainment only and is in many ways,
shapes and forms insecure and underperformant.

A simple linux cli password manager that supports multiple user accounts.

### FEATURES

- Uses Python cryptography library to encrypt stored passwords
- Uses SQLite3 database for storage
- Saves URL, username, and password for each account.

### Requirements

- Python 3.x
- cryptography library
- prettytable library

### Usage

- To register as a user: python main.py -r
- To login as a user: python main.py -l

Follow the prompt to add, view, update, or delete an account.

### Status:

- The bare minimum functionally is operational.
argparse cli application should be properly implemented - #TODO crosscheck RP format and possible improvements
- The users table, in the database, is setup with hashed* passwords using SHA256.
- The account names and urls are being saved in plain text. Passwords are encrypted with Fernet.
- The encryption and decryption key for the accounts are master-password derived using the same
algorithm from users flow (hash.sha256), however here a salt is implement with the PBKDF2HMAC class from
the cryptography library.

### Current Issues:

- need to implement real salt on hashing algorithm - maybe os module
- sanitize sql queries properly

### Pipelined implementations:

##TODO add tests and logs

##TODO prep for packaging, package

##TODO improve display

##TODO try a streamlit version?

##TODO track passwords age

##TODO implement periodic back up of database file

##TODO add password generator

##TODO move sqlite3 to postgres