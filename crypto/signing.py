import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def ecdsa_sign(private_key, message: bytes) -> bytes:
    """
    Sign a message using ECDSA with P-256 and SHA-256.
    Args:
        private_key: EC private key (P-256).
        message:     Raw bytes to sign.
    Returns:
        DER-encoded signature bytes.
    """
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

def ecdsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    """
    Verify an ECDSA signature.

    Args:
        public_key: EC public key (P-256).
        message:    Original message bytes.
        signature:  DER-encoded signature bytes.

    Returns:
        True (valid) / False (invalid).
    """
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def eddsa_sign(private_key, message: bytes) -> bytes:
    """
    Sign a message using EdDSA (Ed25519).

    Args:
        private_key: Ed25519 private key.
        message:     Raw bytes to sign.

    Returns:
        64-byte signature.
    """
    return private_key.sign(message)

def eddsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    """
    Verify an EdDSA (Ed25519) signature.

    Args:
        public_key: Ed25519 public key.
        message:    Original message bytes.
        signature:  64-byte signature.

    Returns:
        True (valid) / False (invalid).
    """
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def signature_to_b64(signature: bytes) -> str:
    """Encode signature bytes to base64 string."""
    return base64.b64encode(signature).decode("utf-8")


def signature_from_b64(b64_str: str) -> bytes:
    """Decode signature from base64 string."""
    return base64.b64decode(b64_str)

if __name__ == "__main__":
    from keys import generate_ecdsa_keypair, generate_eddsa_keypair

    message = b"Hello, this is a test message."
    forged_message = b"Hello, this is a FORGED message."

    # ECDSA tests
    print("=== ECDSA ===")
    ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    _, ecdsa_pub_other = generate_ecdsa_keypair()  # a different keypair

    sig = ecdsa_sign(ecdsa_priv, message)
    print(f"Signature (b64): {signature_to_b64(sig)[:40]}...")
    print(f"Signature size:  {len(sig)} bytes")

    # 1. Valid signature
    assert ecdsa_verify(ecdsa_pub, message, sig), "Should verify!"
    print("Valid signature accepted")

    # 2. Forged message
    assert not ecdsa_verify(ecdsa_pub, forged_message, sig), "Should fail!"
    print("Forged message rejected")

    # 3. Wrong public key
    assert not ecdsa_verify(ecdsa_pub_other, message, sig), "Should fail!"
    print("Wrong public key rejected")

    # 4. Forged signature
    # Checking by flipping bits in the 10th byte which alters the signature
    forged_sig = bytearray(sig)
    forged_sig[10] ^= 0xFF
    assert not ecdsa_verify(ecdsa_pub, message, bytes(forged_sig)), "Should fail!"
    print("Forged signature rejected")

    # EdDSA tests
    print("\n=== EdDSA ===")
    eddsa_priv, eddsa_pub = generate_eddsa_keypair()
    _, eddsa_pub_other = generate_eddsa_keypair()

    sig = eddsa_sign(eddsa_priv, message)
    print(f"Signature (b64): {signature_to_b64(sig)[:40]}...")
    print(f"Signature size:  {len(sig)} bytes")

    # 1. Valid signature
    assert eddsa_verify(eddsa_pub, message, sig), "Should verify!"
    print("Valid signature accepted")

    # 2. Forged message
    assert not eddsa_verify(eddsa_pub, forged_message, sig), "Should fail!"
    print("Forged message rejected")

    # 3. Wrong public key
    assert not eddsa_verify(eddsa_pub_other, message, sig), "Should fail!"
    print("Wrong public key rejected")

    # 4. Forged signature
    # Checking by flipping bits in the 10th byte which alters the signature
    forged_sig = bytearray(sig)
    forged_sig[10] ^= 0xFF
    assert not eddsa_verify(eddsa_pub, message, bytes(forged_sig)), "Should fail!"
    print("Forged signature rejected")


    print("\nAll checks passed.")