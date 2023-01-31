# Password Manager

Disclaimer: This program is for personal entertainment only and is in many ways,
shapes and forms insecure and underperformant.

A simple linux cli password manager that supports multiple user accounts.

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

### Current Issues:

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