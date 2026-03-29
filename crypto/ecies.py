"""
Supported symmetric algorithms:
    - AES-256-GCM          -- block cipher, authentication
    - ChaCha20-Poly1305    -- stream cipher, authentication
    - AES-256-CBC+HMAC     -- block cipher, authentication added by HMAC
"""

import os
import base64
import json
import hmac
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from keys import generate_ecdsa_keypair, public_key_to_b64, public_key_from_b64

ALGO_AES_GCM        = "AES-256-GCM"
ALGO_CHACHA20       = "ChaCha20-Poly1305"
ALGO_AES_CBC_HMAC   = "AES-256-CBC+HMAC-SHA256"

SUPPORTED_ALGORITHMS = [ALGO_AES_GCM, ALGO_CHACHA20, ALGO_AES_CBC_HMAC]

def ecdh_shared_secret(private_key, peer_public_key) -> bytes:
    """
    Perform ECDH key exchange to create a shared secret.

    Args:
        private_key:     Our EC private key.
        peer_public_key: Their EC public key.

    Returns:
        Raw shared secret bytes.
    """
    return private_key.exchange(ec.ECDH(), peer_public_key)

def derive_symmetric_key(shared_secret: bytes, salt: bytes = None, info: bytes = b"ecies") -> bytes:
    """
    Derive a 32-byte symmetric key from an ECDH shared secret using HKDF-SHA256.
    It is not safe using raw shared secret.

    Args:
        shared_secret: Raw bytes from ECDH exchange.
        salt:          Optional random salt (improves security).
        info:          Context/application separation string.
        More at: https://datatracker.ietf.org/doc/html/rfc5869#section-2.3

    Returns:
        32-byte symmetric key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)

def _encrypt_aes_gcm(key: bytes, plaintext: bytes) -> dict:
    nonce      = os.urandom(12)
    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

def _decrypt_aes_gcm(key: bytes, data: dict) -> bytes:
    nonce      = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])
    aesgcm     = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def _encrypt_chacha20(key: bytes, plaintext: bytes) -> dict:
    nonce      = os.urandom(12)
    chacha     = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    return {
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),  # includes 16-byte auth tag
    }


def _decrypt_chacha20(key: bytes, data: dict) -> bytes:
    nonce      = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])
    chacha     = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None)

def _encrypt_aes_cbc_hmac(key: bytes, plaintext: bytes) -> dict:
    """
    AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC).

    Key is split into two halves:
        enc_key = key[:16]  for AES-CBC
        mac_key = key[16:]  for HMAC-SHA256
    """
    enc_key = key[:16]
    mac_key = key[16:]

    # Pad plaintext to AES block size (16 bytes)
    padder    = padding.PKCS7(128).padder()
    padded    = padder.update(plaintext) + padder.finalize()
    # iv == Initialization  vector
    iv        = os.urandom(16)
    cipher    = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # MAC over IV + ciphertext (Encrypt-then-MAC)
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()

    return {
        "iv":         base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "mac":        base64.b64encode(mac).decode(),
    }

def _decrypt_aes_cbc_hmac(key: bytes, data: dict) -> bytes:
    enc_key    = key[:16]
    mac_key    = key[16:]

    iv         = base64.b64decode(data["iv"])
    ciphertext = base64.b64decode(data["ciphertext"])
    mac        = base64.b64decode(data["mac"])

    # Verify MAC before decrypting (timing-safe comparison)
    expected_mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("MAC verification failed — ciphertext tampered!")

    cipher    = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded    = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder  = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def ecies_encrypt(recipient_public_key, plaintext: bytes, algorithm: str = ALGO_AES_GCM) -> dict:
    """
    Encrypt a message using ECIES.

    Args:
        recipient_public_key: Recipient's EC public key.
        plaintext:            Message in bytes.
        algorithm:            Symmetric algorithm to use (from SUPPORTED_ALGORITHMS).

    Returns:
        Dict containing ephemeral public key + encrypted data, ready for transport.

    Raises:
        ValueError: If unsupported algorithm is chosen.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Choose from {SUPPORTED_ALGORITHMS}")

    # 1. Generate ephemeral keypair (single use, never reused)
    ephemeral_priv, ephemeral_pub = generate_ecdsa_keypair()

    # 2. ECDH
    shared_secret = ecdh_shared_secret(ephemeral_priv, recipient_public_key)

    # 3. HKDF -- create symmetric_key from shared_secret
    hkdf_salt      = os.urandom(32)
    symmetric_key  = derive_symmetric_key(shared_secret, salt=hkdf_salt, info=algorithm.encode())

    # 4. Encrypt with chosen symmetric algorithm
    if algorithm == ALGO_AES_GCM:
        encrypted = _encrypt_aes_gcm(symmetric_key, plaintext)
    elif algorithm == ALGO_CHACHA20:
        encrypted = _encrypt_chacha20(symmetric_key, plaintext)
    elif algorithm == ALGO_AES_CBC_HMAC:
        encrypted = _encrypt_aes_cbc_hmac(symmetric_key, plaintext)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # 5. Bundle everything the recipient needs to decrypt
    return {
        "algorithm":        algorithm,
        "ephemeralPublicKey": public_key_to_b64(ephemeral_pub),
        "hkdfSalt":         base64.b64encode(hkdf_salt).decode(),
        "encrypted":        encrypted,
    }

def ecies_decrypt(recipient_private_key, bundle: dict) -> bytes:
    """
    Decrypt an ECIES cryptogram.

    Args:
        recipient_private_key: Recipient's EC private key.
        bundle:                Dict produced by ecies_encrypt().

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If unsupported algorithm is chosen.
    """
    algorithm       = bundle["algorithm"]
    ephemeral_pub   = public_key_from_b64(bundle["ephemeralPublicKey"])
    hkdf_salt       = base64.b64decode(bundle["hkdfSalt"])
    encrypted       = bundle["encrypted"]

    # 1. ECDH -- same shared secret
    shared_secret   = ecdh_shared_secret(recipient_private_key, ephemeral_pub)

    # 2. HKDF -- derive same symmetric key
    symmetric_key   = derive_symmetric_key(shared_secret, salt=hkdf_salt, info=algorithm.encode())

    # 3. Decrypt
    if algorithm == ALGO_AES_GCM:
        return _decrypt_aes_gcm(symmetric_key, encrypted)
    elif algorithm == ALGO_CHACHA20:
        return _decrypt_chacha20(symmetric_key, encrypted)
    elif algorithm == ALGO_AES_CBC_HMAC:
        return _decrypt_aes_cbc_hmac(symmetric_key, encrypted)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

if __name__ == "__main__":
    from keys import generate_ecdsa_keypair

    alice_priv, alice_pub = generate_ecdsa_keypair()
    bob_priv,   bob_pub   = generate_ecdsa_keypair()

    message = b"Very secret message."

    for algo in SUPPORTED_ALGORITHMS:
        print(f"\n=== {algo} ===")

        # 1. Encrypt
        bundle    = ecies_encrypt(bob_pub, message, algorithm=algo)
        json_str  = json.dumps(bundle)
        print(f"Bundle size: {len(json_str)} bytes")

        # 2. Decrypt
        decrypted = ecies_decrypt(bob_priv, bundle)
        assert decrypted == message
        print("Encryption and decryption successful")

        # 3. Wrong private key
        try:
            ecies_decrypt(alice_priv, bundle)
            print("ERROR: should have failed!")
        except Exception:
            print("Wrong private key rejected")

        # 4. Forged ciphertext
        forged = json.loads(json_str)
        ct_bytes = bytearray(base64.b64decode(forged["encrypted"]["ciphertext"]))
        ct_bytes[10] ^= 0xFF
        forged["encrypted"]["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode()
        try:
            ecies_decrypt(bob_priv, forged)
            print("ERROR: should have failed!")
        except Exception:
            print("Forged ciphertext rejected")

    # 5. ECDH symmetry demonstration
    print("\n=== ECDH Symmetry ===")
    secret_ab = ecdh_shared_secret(alice_priv, bob_pub)
    secret_ba = ecdh_shared_secret(bob_priv,   alice_pub)
    assert secret_ab == secret_ba
    print("ECDH produces same secret from both sides")

    print("\nAll checks passed.")

