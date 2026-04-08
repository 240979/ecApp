"""
ca_sign.py

CA admin utility for signing user Certificate Signing Requests (CSRs).

This script is run by the CA admin to:
    1. Load the CA private key (password protected)
    2. Check username is not already registered (encrypted registry)
    3. Read a user's CSR file
    4. Issue two signed certificates:
       - ECDSA certificate (for ECIES encryption)
       - EdDSA certificate (for message signing)
    5. Save certificates to the user's key directory
    6. Add username to encrypted registry

Usage:
    python ca_sign.py --csr client/keys/<username>/csr.json
    python ca_sign.py --revoke <username>
    python ca_sign.py --list
    python ca_sign.py --test
"""

import os
import sys
import json
import base64
import argparse
import getpass

from config import CA_KEYS_DIR, USER_KEYS_DIR, CA_PASSWORD_HASH_FILE
from crypto.keys import load_private_key, public_key_from_b64, derive_key_from_password, verify_password, hash_password
from crypto.certificates import create_certificate, save_certificate
from utils.logger import default_logger as logger

# Encrypted registry

REGISTRY_FILE = os.path.join(CA_KEYS_DIR, "registry.json")


def load_registry(password: str) -> list:
    """
    Load and decrypt the registry of registered usernames.
    Returns empty list if registry does not exist yet.

    Args:
        password: CA admin password.

    Returns:
        List of registered usernames.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not os.path.exists(REGISTRY_FILE):
        return []

    with open(REGISTRY_FILE, "r") as f:
        data = json.load(f)

    salt       = base64.b64decode(data["salt"])
    nonce      = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])

    key = derive_key_from_password(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Failed to decrypt registry — wrong password or file tampered.")

    return json.loads(plaintext.decode("utf-8"))


def save_registry(registry: list, password: str) -> None:
    """
    Encrypt and save the registry of registered usernames.

    Args:
        registry: List of registered usernames.
        password: CA admin password.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt  = os.urandom(32)
    nonce = os.urandom(12)
    key   = derive_key_from_password(password, salt)

    plaintext  = json.dumps(registry).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    os.makedirs(os.path.dirname(REGISTRY_FILE), exist_ok=True)
    with open(REGISTRY_FILE, "w") as f:
        json.dump({
            "salt":       base64.b64encode(salt).decode(),
            "nonce":      base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }, f, indent=2)


#  CSR signing -- create from cert. signing request the cert (in this case actually two of them)

def sign_csr(csr_path: str, ca_password: str, auto_confirm: bool = False) -> tuple:
    """
    Sign a user's CSR and issue two certificates.

    Args:
        csr_path:     Path to the user's CSR JSON file.
        ca_password:  CA admin password.
        auto_confirm: Skip confirmation prompt (for testing).

    Returns:
        (ecdsa_cert, eddsa_cert) — two signed certificate dicts.
    """

    # Load CA private key
    ca_priv_path = os.path.join(CA_KEYS_DIR, "ca_priv.json")

    if not os.path.exists(ca_priv_path):
        print(f"Error: CA private key not found at {ca_priv_path}")
        print("Run: python config.py --generate-ca")
        sys.exit(1)

    try:
        ca_priv = load_private_key(ca_priv_path, ca_password)
        print("CA private key loaded")
    except ValueError:
        print("Error: wrong CA password or key file tampered.")
        sys.exit(1)

    # Load registry
    try:
        registry = load_registry(ca_password)
        print(f"Registry loaded ({len(registry)} registered users)")
    except ValueError:
        print("Error: failed to decrypt registry — wrong password or file tampered.")
        sys.exit(1)

    # Load CSR
    if not os.path.exists(csr_path):
        print(f"Error: CSR file not found at {csr_path}")
        sys.exit(1)

    with open(csr_path, "r") as f:
        csr = json.load(f)

    username  = csr["username"]
    ecdsa_pub = public_key_from_b64(csr["ecdsaPublicKey"])
    eddsa_pub = public_key_from_b64(csr["eddsaPublicKey"])

    print(f"CSR loaded for user: '{username}'")
    print(f"  ECDSA public key: {csr['ecdsaPublicKey'][:40]}...")
    print(f"  EdDSA public key: {csr['eddsaPublicKey'][:40]}...")

    # Check username not already registered
    if username in registry:
        print(f"\nError: username '{username}' is already registered.")
        print(f"To re-register, CA admin must first run: python ca_sign.py --revoke {username}")
        sys.exit(1)

    # Confirm before signing
    confirm = "y" if auto_confirm else input(f"\nSign certificates for '{username}'? (y/n): ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    # Issue certificates
    ecdsa_cert = create_certificate(username, ecdsa_pub, "ECDSA-P256", ca_priv)
    print(f"\nECDSA certificate issued")

    eddsa_cert = create_certificate(username, eddsa_pub, "Ed25519", ca_priv)
    print(f"EdDSA certificate issued")
    logger.log_cert_create(username)
    # Save certificates
    user_dir        = os.path.join(USER_KEYS_DIR, username)
    ecdsa_cert_path = os.path.join(user_dir, "ecdsa_cert.json")
    eddsa_cert_path = os.path.join(user_dir, "eddsa_cert.json")

    os.makedirs(user_dir, exist_ok=True)
    save_certificate(ecdsa_cert, ecdsa_cert_path)
    save_certificate(eddsa_cert, eddsa_cert_path)

    print(f"\nCertificates saved:")
    print(f"  {ecdsa_cert_path}")
    print(f"  {eddsa_cert_path}")

    # Update registry
    registry.append(username)
    save_registry(registry, ca_password)
    print(f"Username '{username}' added to registry")

    return ecdsa_cert, eddsa_cert


def revoke_user(username: str, ca_password: str) -> None:
    """
    Remove a username from the registry, allowing re-registration.

    Args:
        username:    Username to remove.
        ca_password: CA admin password.
    """
    try:
        registry = load_registry(ca_password)
    except ValueError:
        print("Error: failed to decrypt registry.")
        sys.exit(1)

    if username not in registry:
        print(f"Username '{username}' not found in registry.")
        sys.exit(1)

    registry.remove(username)
    save_registry(registry, ca_password)
    print(f"Username '{username}' removed from registry")


def list_users(ca_password: str) -> None:
    """Print all registered usernames."""
    try:
        registry = load_registry(ca_password)
    except ValueError:
        print("Error: failed to decrypt registry.")
        sys.exit(1)

    if not registry:
        print("No users registered yet.")
    else:
        print(f"Registered users ({len(registry)}):")
        for username in registry:
            print(f"  - {username}")


# Self-test

def _selftest():
    import shutil
    from crypto.keys import (
        generate_ecdsa_keypair, generate_eddsa_keypair,
        public_key_to_b64, save_private_key
    ) # Removed hash_password from here, as it's imported from the top of the file
    from crypto.certificates import verify_certificate, load_certificate
    from config import generate_ca_admin_password_hash # Import the new function

    print("=== ca_sign Self-test ===\n")

    # Clean up from previous runs
    test_user_dir = os.path.join(USER_KEYS_DIR, "testuser_casign")
    if os.path.exists(test_user_dir):
        shutil.rmtree(test_user_dir)
    if os.path.exists(REGISTRY_FILE):
        os.remove(REGISTRY_FILE)

    ca_priv_path = os.path.join(CA_KEYS_DIR, "ca_priv.json")
    if not os.path.exists(ca_priv_path):
        print("Error: CA private key not found. Run: python config.py --generate-ca")
        sys.exit(1)

    # Generate and save a test CA admin password hash
    test_ca_admin_password = "test_ca_admin_password123"
    generate_ca_admin_password_hash(test_ca_admin_password)

    # Create a test CSR
    ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    eddsa_priv, eddsa_pub = generate_eddsa_keypair()

    os.makedirs(test_user_dir, exist_ok=True)
    csr = {
        "username":       "testuser_casign",
        "ecdsaPublicKey": public_key_to_b64(ecdsa_pub),
        "eddsaPublicKey": public_key_to_b64(eddsa_pub),
    }
    csr_path = os.path.join(test_user_dir, "csr.json")
    with open(csr_path, "w") as f:
        json.dump(csr, f)
    print("Test CSR created")

    # Authenticate with the test CA admin password
    ca_password = test_ca_admin_password # Use the generated test password for subsequent operations
    if not verify_password(ca_password, json.load(open(CA_PASSWORD_HASH_FILE))["hash"]):
        print("Error: Incorrect CA admin password for self-test.")
        sys.exit(1)
    # Sign it
    ecdsa_cert, eddsa_cert = sign_csr(csr_path, ca_password, auto_confirm=True)

    # Verify certificates
    ca_priv = load_private_key(ca_priv_path, ca_password)
    ca_pub  = ca_priv.public_key()

    assert verify_certificate(ecdsa_cert, ca_pub)
    print("\nECDSA certificate verified")
    assert verify_certificate(eddsa_cert, ca_pub)
    print("EdDSA certificate verified")

    # Check registry
    registry = load_registry(ca_password)
    assert "testuser_casign" in registry
    print("Username in registry")

    # Try registering same username again — should fail
    try:
        sign_csr(csr_path, ca_password, auto_confirm=True)
        print("ERROR: should have rejected duplicate username!")
    except SystemExit:
        print("Duplicate username rejected")

    # Revoke and re-register
    revoke_user("testuser_casign", ca_password)
    registry = load_registry(ca_password)
    assert "testuser_casign" not in registry
    print("Username revoked")

    # List users
    print("\nUser list:")
    list_users(ca_password)

    # Wrong password on registry
    try:
        load_registry("wrongpassword")
        print("ERROR: should have failed!")
    except ValueError:
        print("\nWrong password on registry rejected")

    # Clean up
    shutil.rmtree(test_user_dir)
    os.remove(REGISTRY_FILE)
    print("\nAll checks passed.")


# Main

def main():
    parser = argparse.ArgumentParser(description="ecApp CA signing utility")
    parser.add_argument("--csr",    type=str, help="Path to CSR file to sign")
    parser.add_argument("--revoke", type=str, help="Revoke a username from the registry")
    parser.add_argument("--list",   action="store_true", help="List all registered users")
    parser.add_argument("--test",   action="store_true", help="Run self-test")
    args = parser.parse_args()

    if args.test:
        _selftest()
    elif args.csr:
        # Verify CA admin password against stored hash
        if not os.path.exists(CA_PASSWORD_HASH_FILE):
            print(f"Error: CA admin password not configured. Please run 'python config.py --generate-ca-admin-password' first.")
            sys.exit(1)

        with open(CA_PASSWORD_HASH_FILE, "r") as f:
            stored_ca_admin_hash = json.load(f)["hash"]
        print("=== ecApp CA Signing Utility ===\n")

        ca_password = getpass.getpass("Enter CA admin password: ")
        if not verify_password(ca_password, stored_ca_admin_hash):
            print("Error: Incorrect CA admin password.")
            sys.exit(1)

        sign_csr(args.csr, ca_password)
        print("\n=== Done ===")
    elif args.revoke:
        ca_password = getpass.getpass("Enter CA admin password: ")
        revoke_user(args.revoke, ca_password)
    elif args.list:
        ca_password = getpass.getpass("Enter CA admin password: ")
        list_users(ca_password)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()