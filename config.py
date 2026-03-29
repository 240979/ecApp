"""
This script is meant to set up the CA and then work as default configuration source.

To generate the CA keypair, just run this with --generate-ca --password <admin_password> (just once).
"""

import argparse

# Default port for app to communicate to -- 25519 is from Curve25519
DEFAULT_PORT = 25519

# Crypto defaults:
ALGO_AES_GCM      = "AES-256-GCM"
ALGO_CHACHA20     = "ChaCha20-Poly1305"
ALGO_AES_CBC_HMAC = "AES-256-CBC+HMAC-SHA256"
SUPPORTED_ALGORITHMS = [ALGO_AES_GCM, ALGO_CHACHA20, ALGO_AES_CBC_HMAC]

DEFAULT_SYMMETRIC_ALGO = ALGO_AES_GCM

# CA always uses EdDSA; peers can choose
DEFAULT_SIGNING_ALGO = "EdDSA"

# CA public key (it is hardcoded here, because we didn't want  to bother with some advanced distribution)
CA_PUBLIC_KEY_B64 = "MCowBQYDK2VwAyEAzm7Rxcb2n/6t8Qqx49hmZgfmReFSxKxjthKNCy1aeeo="


def get_ca_public_key():
    """
    Load the hardcoded CA public key.

    Returns:
        CA public key.

    Raises:
        RuntimeError: If CA_PUBLIC_KEY_B64 has not been set yet.
    """
    if CA_PUBLIC_KEY_B64 is None:
        raise RuntimeError(
            "CA public key not configured!\n"
            "Run: python config.py --generate-ca\n"
            "Then paste the printed CA_PUBLIC_KEY_B64 value into config.py."
        )
    from crypto.keys import public_key_from_b64
    return public_key_from_b64(CA_PUBLIC_KEY_B64)

# Dir organization

CA_KEYS_DIR        = "ca/ca_keys"       # CA keys, this is gitignored
USER_KEYS_DIR      = "client/keys"      # User keys, also gitignored
LOG_DIR            = "logs"             # Dir for logs, also gitignored

# Log organization

LOG_ENCRYPT        = True               # encrypt log files at rest
LOG_FILE           = "logs/security.log" # Logfile
LOG_KEY_FILE       = "logs/log.key"     # encrypted log key storage

# Generation of CA keypair

def generate_ca(password: str):
    """
    Generate a fresh CA keypair, save it, and print the public key
    to paste into CA_PUBLIC_KEY_B64.

    Args:
        password: Password to encrypt the CA private key.
    """
    import os
    from crypto.keys import generate_eddsa_keypair, save_private_key, public_key_to_b64

    os.makedirs(CA_KEYS_DIR, exist_ok=True)
    priv, pub = generate_eddsa_keypair()

    priv_path = f"{CA_KEYS_DIR}/ca_priv.json"
    save_private_key(priv, priv_path, password)

    pub_b64 = public_key_to_b64(pub)

    print("\n=== CA keypair generated ===")
    print(f"Private key saved to: {priv_path}  (keep this secret!)")
    print("\nPaste this into config.py as CA_PUBLIC_KEY_B64:\n")
    print(f'CA_PUBLIC_KEY_B64 = "{pub_b64}"')
    print()

    return priv, pub

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ecApp configuration helper")
    parser.add_argument(
        "--generate-ca",
        action="store_true",
        help="Generate a fresh CA keypair and print the public key to paste into config.py"
    )
    parser.add_argument(
        "--password",
        type=str,
        default=None,
        help="Password for CA private key encryption"
    )
    args = parser.parse_args()

    if args.generate_ca:
        password = args.password
        if not password:
            # If the --password is not set, the admin is asked here:
            import getpass
            password = getpass.getpass("Enter password for CA private key: ")
        generate_ca(password)
    else:
        print("ecApp Configuration")
        print(f"  Default algorithm:  {DEFAULT_SYMMETRIC_ALGO}")
        print(f"  Supported algorithms: {', '.join(SUPPORTED_ALGORITHMS)}")
        print(f"  CA key configured:  {'Yes' if CA_PUBLIC_KEY_B64 else 'No — run --generate-ca'}")