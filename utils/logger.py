"""
Event logger for crypto app.
Logs:
    - Key generation
    - Certificate creation and verification
    - Signing and verification
    - Encryption and decryption
    - ECDH key exchange
    - Authentication failures
    - Tampering detection
Log format (each entry is a JSON line):
    {
        "timestamp":  "1970-01-01T12:00:00.000000",
        "event":      "SIGN",
        "algorithm":  "EdDSA",
        "data_size":  128,
        "result":     "OK" | "FAIL",
        "details":    "optional extra info"
    }
Log can be encrypted with AES-GCM
"""
import os
import json
import base64
import logging
from datetime import datetime, timezone
import config

# Events

EVENT_KEY_GEN = "KEY_GEN"           # keypair generated
EVENT_CERT_CREATE = "CERT_CREATE"   # certificate created
EVENT_CERT_VERIFY = "CERT_VERIFY"   # certificate verified
EVENT_SIGN = "SIGN"                 # message signed
EVENT_VERIFY = "VERIFY"             # signature verified
EVENT_ENCRYPT = "ENCRYPT"           # message encrypted
EVENT_DECRYPT = "DECRYPT"           # message decrypted
EVENT_ECDH = "ECDH"                 # ECDH key exchange performed
EVENT_AUTH_FAIL = "AUTH_FAIL"       # authentication failure
EVENT_TAMPER = "TAMPER"             # tampering detected

RESULT_OK = "OK"
RESULT_FAIL = "FAIL"


class SecurityLogger:
    """
    Logs security events to a file in JSON Lines format.
    Each line in the log file is a self-contained JSON object.

    Optionally encrypts the log file at rest using AES-256-GCM.
    """

    def __init__(self, log_file: str, encrypt: bool = False, key: bytes = None):
        """
        Initialize the security logger.

        Args:
            log_file: Path to the log file.
            encrypt:  Whether to encrypt log entries at rest.
            key:      32-byte AES key for encryption (required if encrypt=True).
        """
        self.log_file = log_file
        self.encrypt = encrypt
        self.key = key

        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        # Also log to console via Python's standard logging
        self._console = logging.getLogger("security")
        if not self._console.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            self._console.addHandler(handler)
            self._console.setLevel(logging.INFO)

    def _write(self, entry: dict) -> None:
        """Write a log entry to the log file."""
        line = json.dumps(entry, separators=(",", ":"))

        if self.encrypt and self.key:
            line = self._encrypt_line(line)

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def _encrypt_line(self, line: str) -> str:
        """
        Encrypt a single log line with AES-256-GCM.
        Returns a JSON string containing nonce + ciphertext.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, line.encode("utf-8"), None)
        encrypted = {
            "enc": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
        }
        return json.dumps(encrypted, separators=(",", ":"))

    def _decrypt_line(self, line: str) -> str:
        """Decrypt a single encrypted log line."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        data = json.loads(line)
        nonce = base64.b64decode(data["nonce"])
        ciphertext = base64.b64decode(data["enc"])
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")

    def log(self, event: str, result: str, algorithm: str = None,
            data_size: int = None, details: str = None) -> None:
        """
        Log a security event.

        Args:
            event:      Event type.
            result:     RESULT_OK or RESULT_FAIL.
            algorithm:  Cryptographic algorithm used.
            data_size:  Size of data in bytes.
            details:    Optional extra information.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "result": result,
        }
        if algorithm: entry["algorithm"] = algorithm
        if data_size: entry["data_size"] = data_size
        if details:   entry["details"] = details

        self._write(entry)

        # Also print to console
        status = "✓" if result == RESULT_OK else "✗"
        algo = f" [{algorithm}]" if algorithm else ""
        size = f" {data_size}B" if data_size else ""
        detail = f" — {details}" if details else ""
        self._console.info(f"{status} {event}{algo}{size}{detail}")

    def enable_secure_logging(self, key: bytes):
        """
        Provides the master key to the logger, enabling
        AES-GCM encryption for all future entries.
        """
        self.key = key
        self.encrypt = True
        self._console.info("Secure logging mode: ENABLED")

    def read_logs(self) -> list:
        """Reads logs, automatically decrypting lines if the key is available."""
        if not os.path.exists(self.log_file):
            return []

        entries = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    data = json.loads(line)
                    # Detect if this specific line is an encrypted blob
                    if "enc" in data and "nonce" in data:
                        if not self.key:
                            # Log is encrypted but we haven't unlocked yet
                            entries.append({
                                "timestamp": "LOCKED", "event": "SECURE_ENTRY",
                                "result": "???", "details": "Unlock as Admin to view"
                            })
                        else:
                            decrypted_line = self._decrypt_line(line)
                            entries.append(json.loads(decrypted_line))
                    else:
                        # Standard plaintext JSON line
                        entries.append(data)
                except Exception:
                    continue
        return entries


    def log_key_gen(self, algorithm: str):
        self.log(EVENT_KEY_GEN, RESULT_OK, algorithm=algorithm)

    def log_cert_create(self, subject: str):
        self.log(EVENT_CERT_CREATE, RESULT_OK, details=f"subject={subject}")

    def log_cert_verify(self, subject: str, success: bool):
        result = RESULT_OK if success else RESULT_FAIL
        self.log(EVENT_CERT_VERIFY, result, details=f"subject={subject}")

    def log_sign(self, algorithm: str, data_size: int):
        self.log(EVENT_SIGN, RESULT_OK, algorithm=algorithm, data_size=data_size)

    def log_verify(self, algorithm: str, data_size: int, success: bool):
        result = RESULT_OK if success else RESULT_FAIL
        self.log(EVENT_VERIFY, result, algorithm=algorithm, data_size=data_size)

    def log_encrypt(self, algorithm: str, data_size: int):
        self.log(EVENT_ENCRYPT, RESULT_OK, algorithm=algorithm, data_size=data_size)

    def log_decrypt(self, algorithm: str, data_size: int, success: bool):
        result = RESULT_OK if success else RESULT_FAIL
        self.log(EVENT_DECRYPT, result, algorithm=algorithm, data_size=data_size)

    def log_ecdh(self):
        self.log(EVENT_ECDH, RESULT_OK)

    def log_auth_fail(self, details: str):
        self.log(EVENT_AUTH_FAIL, RESULT_FAIL, details=details)

    def log_tamper(self, details: str):
        self.log(EVENT_TAMPER, RESULT_FAIL, details=details)

# Log security management

def generate_log_key(key_file: str, password: str) -> bytes:
    """
    Generate a random AES-256 key for log encryption,
    encrypt it with the user's password and save to disk.

    Args:
        key_file: Path to save the encrypted log key.
        password: Password to encrypt the log key.

    Returns:
        The generated 32-byte log key.
    """
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from crypto.keys import derive_key_from_password, save_private_key
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    log_key = os.urandom(32)
    salt = os.urandom(32)
    nonce = os.urandom(12)
    enc_key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(enc_key)
    ct = aesgcm.encrypt(nonce, log_key, None)

    os.makedirs(os.path.dirname(key_file), exist_ok=True)
    with open(key_file, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
        }, f, indent=2)

    return log_key


def load_log_key(key_file: str, password: str) -> bytes:
    """
    Load and decrypt the log encryption key from disk.

    Args:
        key_file: Path to the encrypted log key file.
        password: Password to decrypt the log key.

    Returns:
        The 32-byte log key.
    """
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from crypto.keys import derive_key_from_password
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    with open(key_file, "r") as f:
        data = json.load(f)

    salt = base64.b64decode(data["salt"])
    nonce = base64.b64decode(data["nonce"])
    ct = base64.b64decode(data["ciphertext"])

    enc_key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(enc_key)

    try:
        return aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Failed to decrypt log key — wrong password or file tampered.")

# Default global logger
default_logger = SecurityLogger("logs/security.log", encrypt=False)