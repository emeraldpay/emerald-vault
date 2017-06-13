# API for interaction between connector and UI:

## `emerald_newAccount(name, desc, pass)`

    Creates new keystore file and caches it.

    Arguments:
        * name - name for account (optional)
        * desc - free form description (optional)
        * pass - passphrase used to encode keyfile

    Result:
        * addr - address of created keyfile

## `emerald_importWallet(kf)`

    Import previously created keystore file into connector.

    Arguments:

        * kf - keyfile to be imported into connector

    Result:
        * addr - address of impored keyfile


## `emerald_signTransaction(tr, pass)`

    Signs transaction with private key from keystore file by given passphrase.

    Arguments:

        * tr - given transaction
        * pass - passphrase used to extract private key

    Result:
        tr_signed - signed transaction encoded into `RLP` format
