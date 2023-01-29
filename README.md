# EnPasMan

### En Password Manager

A simple linux cli password manager that supports multiple user accounts.

- The name may be derived from the french term used in chess - 'En Passant'
see https://en.wikipedia.org/wiki/En_passant

Status:
The bare minimum functionally is operational.
argparse cli application should be properly implemented - #TODO crosscheck RP format and possible improvements
The Users table, in the database, is set with hashed passwords using SHA256.
The account names and urls are being saved in plain text. Passwords are encrypted with Fernet.
The decryption key for the accounts is master-password derived using the same
algorithm from users flow (hash.sha256), however here a salt is implement with the PBKDF2HMAC class from
the cryptography library.

Current Issues:
- need to implement real salt - os module?
- sanitize sql queries properly

##TODO add tests and logs

##TODO prep for packaging, package

##TODO improve display

##TODO try a streamlit version?

##TODO track passwords age

##TODO implement periodic back up of database file

##TODO add password generator