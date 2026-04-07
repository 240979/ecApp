"""
Certificates have this format:
{
    "issuer":             "CA",
    "publicKey":          "<base64 DER public key>",
    "publicKeyAlgorithm": "Ed25519" | "ECDSA-P256",
    "signature":          "<base64 CA signature>"
    "subject":            "<username>",
}
Signature should sign all previous values, but not itself.
"""

import json
import os

from crypto.keys import (
    public_key_to_b64,
    public_key_from_b64,
    save_private_key,
    save_public_key,
)
from crypto.signing import eddsa_sign, eddsa_verify, signature_to_b64, signature_from_b64


def _cert_payload(cert: dict) -> bytes:
    """
    Keys are sorted alphabetically, no extra whitespace.
    Args:
        cert: Certificate dict (may or may not contain 'signature' key).
    Returns:
        UTF-8 encoded JSON bytes.
    """
    payload = {}
    for k, v in cert.items():
        if k != "signature":
            # Ignore signature
            payload[k] = v
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

def create_certificate(
    subject: str,
    public_key,
    public_key_algorithm: str,
    ca_private_key,
) -> dict:
    """
    Create a signed certificate binding a username to a public key.

    Args:
        subject:              Username to bind.
        public_key:           User's public key object.
        public_key_algorithm: "Ed25519" or "ECDSA-P256".
        ca_private_key:       CA's private key for signing.

    Returns:
        Certificate dict including the CA signature.
    """
    cert = {
        "subject":            subject,
        "publicKey":          public_key_to_b64(public_key),
        "publicKeyAlgorithm": public_key_algorithm,
        "issuer":             "CA",
    }

    payload   = _cert_payload(cert)
    signature = eddsa_sign(ca_private_key, payload)
    # Add signature separately
    cert["signature"] = signature_to_b64(signature)
    return cert

def verify_certificate(cert: dict, ca_public_key) -> bool:
    """
    Verify a certificate's CA signature.

    Args:
        cert:          Certificate dict containing a 'signature' field.
        ca_public_key: CA's public key object.

    Returns:
        True (valid) / False (invalid).
    """
    try:
        signature = signature_from_b64(cert["signature"])
        payload   = _cert_payload(cert)
        return eddsa_verify(ca_public_key, payload, signature)
    except Exception:
        return False

def get_public_key_from_cert(cert: dict):
    """
    Extract and deserialize the user's public key from a certificate.

    Args:
        cert: A verified certificate dict.

    Returns:
        Public key.
    """
    return public_key_from_b64(cert["publicKey"])

def save_certificate(cert: dict, filepath: str) -> None:
    """Save a certificate as a plain JSON file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(cert, f, indent=2)


def load_certificate(filepath: str) -> dict:
    """Load a certificate from a JSON file."""
    with open(filepath, "r") as f:
        return json.load(f)

def setup_ca(ca_dir: str, password: str):
    """
    Generate and save a new CA keypair. Run this once to initialize the CA.

    Saves:
        <ca_dir>/ca_private.json  -- encrypted with password
        <ca_dir>/ca_public.json   -- plain (somehow distributed to all clients)

    Args:
        ca_dir:   Directory to store CA keys.
        password: Password to encrypt the CA private key.
    """
    ca_priv, ca_pub = generate_eddsa_keypair()
    save_private_key(ca_priv, os.path.join(ca_dir, "ca_private.json"), password)
    save_public_key(ca_pub, os.path.join(ca_dir, "ca_public.json"))
    print(f"CA keypair generated and saved to {ca_dir}/")
    return ca_priv, ca_pub

if __name__ == "__main__":
    from keys import generate_ecdsa_keypair, generate_eddsa_keypair

    # Generate CA keypair
    print("=== CA Setup ===")
    ca_priv, ca_pub = generate_eddsa_keypair()
    print("CA keypair generated")

    # Generate user keypairs
    ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    eddsa_priv, eddsa_pub = generate_eddsa_keypair()

    # Create certificates
    print("\n=== Certificate Creation ===")
    cert_ecdsa = create_certificate("alice", ecdsa_pub, "ECDSA-P256", ca_priv)
    cert_eddsa = create_certificate("bob",   eddsa_pub, "Ed25519",    ca_priv)
    print(f"Certificate for alice (ECDSA): {json.dumps(cert_ecdsa, indent=2)}")
    print(f"\nCertificate for bob (EdDSA):   {json.dumps(cert_eddsa, indent=2)}")

    # Valid certificates
    print("\n=== Verification ===")
    assert verify_certificate(cert_ecdsa, ca_pub), "Should verify!"
    print("Alice's certificate verified")

    assert verify_certificate(cert_eddsa, ca_pub), "Should verify!"
    print("Bob's certificate verified")

    # Wrong CA public key
    _, fake_ca_pub = generate_eddsa_keypair()
    assert not verify_certificate(cert_ecdsa, fake_ca_pub), "Should fail!"
    print("Wrong CA public key rejected")

    # Forged certificate (username changed)
    forged_cert = dict(cert_ecdsa)
    forged_cert["subject"] = "eve"
    assert not verify_certificate(forged_cert, ca_pub), "Should fail!"
    print("Forged subject rejected")

    # Forged certificate (public key swapped)
    _, attacker_pub = generate_ecdsa_keypair()
    forged_cert2 = dict(cert_ecdsa)
    forged_cert2["publicKey"] = public_key_to_b64(attacker_pub)
    assert not verify_certificate(forged_cert2, ca_pub), "Should fail!"
    print("Forged public key rejected")

    # Forged signature
    forged_cert3 = dict(cert_ecdsa)
    sig_bytes = signature_from_b64(forged_cert3["signature"])
    forged_sig = bytearray(sig_bytes)
    forged_sig[10] ^= 0xFF
    # Again flipping bits in 10th byte to simulate manipulation with signature
    forged_cert3["signature"] = signature_to_b64(bytes(forged_sig))
    assert not verify_certificate(forged_cert3, ca_pub), "Should fail!"
    print("Forged signature rejected")

    # Extract public key from cert
    print("\n=== Key Extraction ===")
    extracted_pub = get_public_key_from_cert(cert_ecdsa)
    assert public_key_to_b64(extracted_pub) == public_key_to_b64(ecdsa_pub)
    print("Public key extracted from certificate correctly")

    # Save and load
    print("\n=== Save & Load ===")
    save_certificate(cert_ecdsa, "test_keys/alice_cert.json")
    loaded_cert = load_certificate("test_keys/alice_cert.json")
    assert verify_certificate(loaded_cert, ca_pub)
    print("Certificate saved and loaded correctly")

    print("\nAll checks passed.")