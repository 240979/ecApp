import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher

NONCE_SIZE        = 12        # bytes, standard for AES-GCM
KEY_SIZE          = 32        # bytes, AES-256
SALT_SIZE        = 16    # bytes
ARGON2_TIME      = 2     # iterations
ARGON2_MEMORY    = 19456 # KiB = 19 MiB
ARGON2_THREADS   = 1     # parallelism
# Got it from https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a password using Argon2id.
    OWASP recommended parameters: 19 MiB memory, 2 iterations, 1 thread.
    """
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_THREADS,
        hash_len=KEY_SIZE,
        type=Type.ID,      # ID = Argon2id
    )

def generate_ecdsa_keypair():
    """
    Elliptic Curves keypair generation
    Returns:
        (private_key, public_key)
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()

def generate_eddsa_keypair():
    """
    Edwards Curves keypair generation
    Returns:
        (private_key, public_key)
    """
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()

def public_key_to_b64(public_key) -> str:
    """Serialize a public key to base64-encoded DER bytes."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("utf-8")


def public_key_from_b64(b64_str: str):
    """Deserialize a public key from base64-encoded DER bytes."""
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    der = base64.b64decode(b64_str)
    return load_der_public_key(der)


def private_key_to_pem(private_key) -> bytes:
    """Serialize a private key to unencrypted PEM bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_key_from_pem(pem: bytes):
    """Deserialize a private key from unencrypted PEM bytes."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(pem, password=None)

def save_private_key(private_key, filepath: str, password: str) -> None:
    """
    Save private key to local drive.
    It is encrypted with AES-GCM using key derived from password (argon2).

    File format (JSON):
    {
        "salt":       "<base64>",   # PBKDF2 salt
        "nonce":      "<base64>",   # AES-GCM nonce
        "ciphertext": "<base64>"    # encrypted PEM + GCM auth tag
    }

    Args:
        private_key: Private key object.
        filepath:    Path to file.
        password:    User's password for key derivation.
    """
    salt  = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    derived_key = derive_key_from_password(password, salt)
    plaintext   = private_key_to_pem(private_key)

    aesgcm     = AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # no AAD needed here

    payload = {
        "salt":       base64.b64encode(salt).decode(),
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(payload, f, indent=2)

def load_private_key(filepath: str, password: str):
    """
    Load private key from local drive.

    Args:
        filepath: Path to file.
        password: User's password for key derivation.

    Returns:
        Private key.

    Raises:
        ValueError:      If decryption fails (wrong password or tampered file).
        FileNotFoundError: If the file does not exist.
    """
    with open(filepath, "r") as f:
        payload = json.load(f)

    salt       = base64.b64decode(payload["salt"])
    nonce      = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    derived_key = derive_key_from_password(password, salt)
    aesgcm      = AESGCM(derived_key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Failed to decrypt private key — wrong password or file tampered.")

    return private_key_from_pem(plaintext)

def save_public_key(public_key, filepath: str) -> None:
    """Save a public key as plain base64 JSON."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump({"publicKey": public_key_to_b64(public_key)}, f, indent=2)


def load_public_key(filepath: str):
    """Load a public key from JSON."""
    with open(filepath, "r") as f:
        payload = json.load(f)
    return public_key_from_b64(payload["publicKey"])

ph = PasswordHasher()

def hash_password(password: str) -> str:
    """Returns a single string containing algorithm, params, salt and hash."""
    return ph.hash(password)

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        ph.verify(stored_hash, password)
        return True
    except Exception:
        return False

if __name__ == "__main__":
    print("=== Key Generation ===")

    ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    print(f"ECDSA  public key: {public_key_to_b64(ecdsa_pub)[:40]}...")

    eddsa_priv, eddsa_pub = generate_eddsa_keypair()
    print(f"EdDSA  public key: {public_key_to_b64(eddsa_pub)[:40]}...")

    print("\n=== Save & Load (ECDSA) ===")
    save_private_key(ecdsa_priv, "test_keys/ecdsa_priv.json", "heslo123")
    save_public_key(ecdsa_pub,   "test_keys/ecdsa_pub.json")
    loaded = load_private_key("test_keys/ecdsa_priv.json", "heslo123")
    assert public_key_to_b64(loaded.public_key()) == public_key_to_b64(ecdsa_pub)
    print("ECDSA key saved and loaded correctly ✓")

    print("\n=== Wrong password ===")
    try:
        load_private_key("test_keys/ecdsa_priv.json", "wrongpassword")
    except ValueError as e:
        print(f"Rejected wrong password: {e}")

    print("\n=== Password hashing ===")
    record = hash_password("mysecretpassword")
    assert verify_password("mysecretpassword", record)
    assert not verify_password("wrongpassword", record)
    print("Password hashing and verification works")

    print("\nAll checks passed.")
