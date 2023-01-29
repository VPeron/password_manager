# EnPasMan

### En Password Manager

- The name may be derived from french term used in chess - 'En Passant'
see https://en.wikipedia.org/wiki/En_passant

Status:
The bare minimum functionally is operational.
Cli should be properly invoked - #TODO crosscheck RP format and possible improvements
The Users table, in the database, is properly set with hashed passwords using SHA256.
The accounts are being saved in plain text. Passwords are encrypted with Fernet.
The key is master-password derived for the accounts password encrption using the same
algorithm hash.sha256 

Current Issues:
- need to implement real salt from os module

## TODO add tests and logs
## TODO prep for packaging, package
## TODO improve display
## TODO move password input directly into hashing function
## TODO improve hashing function
## TODO enforce strong password
## TODO try a streamlit version?
## TODO track passwords age
## TODO implement periodic back up of database file