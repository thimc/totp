# totp

_DISCLAIMER: I am not a security expert so I wouldn't necessarily
recommend you to use this for your actual passwords.  This project
simply exists on my github so that I can use it across many devices._

totp is a TOTP (Time-based one-time password) authenticator as
specified by RFC6238 and is made to work well with other programs,
in that way it is almost homogeneous with "pass(1) - the standard
unix password manager".

## Usage

To use totp you will either need to pipe the data to totp or specify
a file with your secrets (using the -f flag). The input should
contain two tab-separated fields:
1. The first field is an identifier for what the temporary password
will be for. This is up to the user to decide and will not affect
the outcome of the secrets. __Note that the field is truncated at 25
characters.__
2. The second (and last) field is the secret key.


I recommend keeping a GnuPG encrypted file with all the secrets on disk
and adding a alias in your shell to use totp:

    totp='gpg -qd $HOME/.totp.gpg 2>/dev/null | (which totp)'

## License
MIT
