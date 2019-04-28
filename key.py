from jwcrypto import jwk


def load_key(key_path: str):
    global key

    # Load the RSA keys from the keys folder
    with open(key_path, mode="rb") as key_file:
        # Create JWK from file
        key = jwk.JWK.from_pem(key_file.read())


def get_signing_key():
    return key
