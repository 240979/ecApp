"""
register.py

User registration utility for the ecApp peer-to-peer encrypted communication app.

This script is run by a new user to:
    1. Choose a username and password
    2. Generate ECDSA P-256 keypair  (for ECIES encryption + ECDSA signing)
    3. Generate EdDSA Ed25519 keypair (for EdDSA signing)
    4. Save both private keys encrypted with the user's password
    5. Produce a Certificate Signing Request (CSR) file for the CA admin to sign

After running this script, the user sends their CSR file to the CA admin,
who runs ca_sign.py to issue the certificates.

Usage:
    python register.py
"""

import os
import json
import sys
import getpass

from config import USER_KEYS_DIR
from crypto.keys import (
    generate_ecdsa_keypair,
    generate_eddsa_keypair,
    save_private_key,
    public_key_to_b64,
    hash_password,
)


def register():
    print("=== ecApp User Registration ===\n")

    # 1: Username
    username = input("Choose a username: ").strip()
    if not username:
        print("Error: username cannot be empty.")
        input("\nPress Enter to return to the main menu...")
        return


    user_dir = os.path.join(USER_KEYS_DIR, username)

    if os.path.exists(user_dir):
        print(f"Error: user '{username}' already exists locally.")
        input("\nPress Enter to return to the main menu...")
        return
    # Prevent slashes in username
    if "/" in username or "\\" in username:
        print("Error: username cannot contain slashes ('/' or '\\').")
        input("\nPress Enter to return to the main menu...")
        return

    # 2: Password
    password = getpass.getpass("Choose a password (password must be at least 8 characters): ")
    password_confirm = getpass.getpass("Confirm password: ")

    if password != password_confirm:
        print("Error: passwords do not match.")
        input("\nPress Enter to return to the main menu...")
        return

    if len(password) < 8:
        print("Error: password must be at least 8 characters.")
        input("\nPress Enter to return to the main menu...")
        return

    # 3: Generate keypairs
    print("\nGenerating keypairs...")

    ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    print("  ECDSA P-256 keypair generated")

    eddsa_priv, eddsa_pub = generate_eddsa_keypair()
    print("  EdDSA Ed25519 keypair generated")

    # 4: Save private keys encrypted
    os.makedirs(user_dir, exist_ok=True)

    ecdsa_priv_path = os.path.join(user_dir, "ecdsa_priv.json")
    eddsa_priv_path = os.path.join(user_dir, "eddsa_priv.json")

    save_private_key(ecdsa_priv, ecdsa_priv_path, password)
    print(f"  ECDSA private key saved to {ecdsa_priv_path}")

    save_private_key(eddsa_priv, eddsa_priv_path, password)
    print(f"  EdDSA private key saved to {eddsa_priv_path}")

    # 5: Save password hash
    password_hash = hash_password(password)
    password_hash_path = os.path.join(user_dir, "password.json")
    with open(password_hash_path, "w") as f:
        json.dump(password_hash, f, indent=2)
    print(f"  Password hash saved to {password_hash_path}")

    # 6: Produce CSR (certificate signing request)
    csr = {
        "username":        username,
        "ecdsaPublicKey":  public_key_to_b64(ecdsa_pub),
        "eddsaPublicKey":  public_key_to_b64(eddsa_pub),
    }

    csr_path = os.path.join(user_dir, "csr.json")
    with open(csr_path, "w") as f:
        json.dump(csr, f, indent=2)

    print(f"\n  CSR saved to {csr_path}")

    # 7: Instructions
    print(f"""
=== Registration complete ===

Your keys have been saved to: {user_dir}

Next step:
    Send your CSR file to the CA admin:
    {csr_path}

The CA admin will run:
    python ca_sign.py --csr {csr_path}
    or will use main app interface to sign

And send back two certificate files:
    {os.path.join(user_dir, "ecdsa_cert.json")}
    {os.path.join(user_dir, "eddsa_cert.json")}

Once you have your certificates, you can run the app.
""")


# ── Quick self-test ───────────────────────────────────────────────────────────

def _selftest():
    import shutil
    from crypto.keys import load_private_key, verify_password

    print("=== Registration Self-test ===\n")

    # Clean up from previous test runs
    test_dir = os.path.join(USER_KEYS_DIR, "testuser")
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)

    # Simulate registration
    username  = "testuser"
    password  = "testpassword123"
    user_dir  = os.path.join(USER_KEYS_DIR, username)

    os.makedirs(user_dir, exist_ok=True)

    ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    eddsa_priv, eddsa_pub = generate_eddsa_keypair()

    ecdsa_priv_path = os.path.join(user_dir, "ecdsa_priv.json")
    eddsa_priv_path = os.path.join(user_dir, "eddsa_priv.json")

    save_private_key(ecdsa_priv, ecdsa_priv_path, password)
    save_private_key(eddsa_priv, eddsa_priv_path, password)

    # Save password hash
    password_hash = hash_password(password)
    with open(os.path.join(user_dir, "password.json"), "w") as f:
        json.dump(password_hash, f)

    # Save CSR
    csr = {
        "username":       username,
        "ecdsaPublicKey": public_key_to_b64(ecdsa_pub),
        "eddsaPublicKey": public_key_to_b64(eddsa_pub),
    }
    with open(os.path.join(user_dir, "csr.json"), "w") as f:
        json.dump(csr, f)

    # Verify keys can be loaded back
    loaded_ecdsa = load_private_key(ecdsa_priv_path, password)
    assert public_key_to_b64(loaded_ecdsa.public_key()) == public_key_to_b64(ecdsa_pub)
    print("ECDSA private key saved and loaded correctly")

    loaded_eddsa = load_private_key(eddsa_priv_path, password)
    assert public_key_to_b64(loaded_eddsa.public_key()) == public_key_to_b64(eddsa_pub)
    print("EdDSA private key saved and loaded correctly")

    # Verify password hash
    with open(os.path.join(user_dir, "password.json"), "r") as f:
        stored = json.load(f)
    assert verify_password(password, stored)
    assert not verify_password("wrongpassword", stored)
    print("Password hash verified correctly")

    # Verify CSR contents
    with open(os.path.join(user_dir, "csr.json"), "r") as f:
        loaded_csr = json.load(f)
    assert loaded_csr["username"] == username
    assert loaded_csr["ecdsaPublicKey"] == public_key_to_b64(ecdsa_pub)
    assert loaded_csr["eddsaPublicKey"] == public_key_to_b64(eddsa_pub)
    print("CSR contents verified correctly")

    # Clean up
    shutil.rmtree(test_dir)
    print("\nAll checks passed.")


if __name__ == "__main__":
    if "--test" in sys.argv:
        _selftest()
    else:
        register()