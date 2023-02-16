# Password Manager

- A simple linux cli password manager that supports multiple user accounts.

Disclaimer: This program is for personal entertainment only and is in many ways,
shapes and forms insecure and underperformant. Suggestions and discussions are most
welcome but PRs will likely be declined as the intent is to educate myself.

### FEATURES

- Register and login multiple user accounts within the same database
- Uses Python cryptography library to hash or encrypt stored passwords
- Uses SQLite3 database for persistency, maybe this will scale to posgres
- Saves a URL, username, and password for each account
- View, Edit and Delete functionalities

### Requirements

- Python 3.x
- cryptography library
- prettytable library
- Pillow
- pyperclip (On linux xclip may be required for pyperclip to work)

### Usage

- To register as a user: python3 main.py -r

NOTE: The main intention is for single user user within a local network but one may need a personal and professional accounts, for instance, separated.

- To login as a user: python3 main.py -l

- Follow the prompt to to enter the username and password, then to add, view, update, or delete an account.

### Status:

- Simple cli application with argparse
- The users table stores hashed passwords using SHA256.
- In Accounts, the account names and urls are being saved in plain text. Passwords are encrypted with Fernet.
- The encryption and decryption key for the accounts are master-password derived using the same
algorithm from users flow (hash.sha256). here salt is implemented with the PBKDF2HMAC class still from
the cryptography library.

### Pipelined implementations:

##TODO improve tests

##TODO prep for packaging, package

##TODO track passwords age

##TODO implement periodic back up of database file

##TODO improve key derivations (time stamp?)

### Snowball in Hell and Current Issues:

- sanitize sql queries properly

## Rerences

- ascii art script: https://github.com/kiteco/python-youtube-code/blob/master/ascii/ascii_convert.py
