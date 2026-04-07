"""
network/protocol.py

Message framing and serialization for the ecApp peer-to-peer encrypted communication app.

Every message sent over the network is a JSON object with the following structure:
{
    "type":    "<message type>",
    "payload": { ... }             # type-specific data
}

Message types:
    HELLO       - initial handshake, exchange certificates
    HELLO_ACK   - acknowledgement of HELLO, confirm identity
    MESSAGE     - encrypted message from peer
    SIGN_ONLY   - signed but unencrypted message (for demo purposes)
    ERROR       - error notification
    BYE         - graceful disconnect

Framing:
    Messages are sent over TCP as:
    [4 bytes: message length (big-endian uint32)] [message bytes (UTF-8 JSON)]

    The length prefix allows the receiver to know exactly how many bytes to read,
    solving the TCP stream fragmentation problem.
"""

import json
import struct
import socket

# ── Message types ─────────────────────────────────────────────────────────────

MSG_HELLO       = "HELLO"        # send certificate + supported algorithms
MSG_HELLO_ACK   = "HELLO_ACK"   # confirm peer identity
MSG_MESSAGE     = "MESSAGE"      # encrypted message
MSG_SIGN_ONLY   = "SIGN_ONLY"   # signed plaintext message (demo)
MSG_ERROR       = "ERROR"        # error notification
MSG_BYE         = "BYE"         # graceful disconnect

# ── Framing constants ─────────────────────────────────────────────────────────

HEADER_SIZE  = 4          # bytes for length prefix
MAX_MSG_SIZE = 10_485_760 # 10 MB max message size


# ── Message construction ──────────────────────────────────────────────────────

def make_message(msg_type: str, payload: dict) -> dict:
    """
    Construct a protocol message dict.

    Args:
        msg_type: One of the MSG_* constants.
        payload:  Type-specific data dict.

    Returns:
        Message dict ready for serialization.
    """
    return {
        "type":    msg_type,
        "payload": payload,
    }


def make_hello(ecdsa_certificate: dict, eddsa_certificate: dict, supported_algorithms: list) -> dict:
    """
    Construct a HELLO message carrying the sender's ECDSA and EdDSA certificates.

    Args:
        ecdsa_certificate:     Sender's ECDSA certificate dict.
        eddsa_certificate:     Sender's EdDSA certificate dict.
        supported_algorithms:  List of symmetric algorithms the sender supports.
    """
    return make_message(MSG_HELLO, {
        "ecdsaCertificate":     ecdsa_certificate,
        "eddsaCertificate":     eddsa_certificate,
        "supportedAlgorithms":  supported_algorithms,
    })


def make_hello_ack(ecdsa_certificate: dict, eddsa_certificate: dict, chosen_algorithm: str) -> dict:
    """
    Construct a HELLO_ACK message confirming the handshake.

    Args:
        ecdsa_certificate: Responder's ECDSA certificate dict.
        eddsa_certificate: Responder's EdDSA certificate dict.
        chosen_algorithm: Symmetric algorithm agreed upon for this session.
    """
    return make_message(MSG_HELLO_ACK, {
        "ecdsaCertificate":     ecdsa_certificate,
        "eddsaCertificate":     eddsa_certificate,
        "chosenAlgorithm": chosen_algorithm,
    })


def make_encrypted_message(ecies_bundle: dict, signature: str, signing_algorithm: str) -> dict:
    """
    Construct an encrypted MESSAGE.

    Args:
        ecies_bundle:      Output of ecies_encrypt() — the encrypted payload.
        signature:         Base64 signature over the ciphertext bundle.
        signing_algorithm: "ECDSA" or "EdDSA".
    """
    return make_message(MSG_MESSAGE, {
        "eciesBundle":      ecies_bundle,
        "signature":        signature,
        "signingAlgorithm": signing_algorithm,
    })


def make_sign_only_message(plaintext: str, signature: str, signing_algorithm: str) -> dict:
    """
    Construct a signed-but-unencrypted message (for demo/testing purposes).

    Args:
        plaintext:         The plaintext message string.
        signature:         Base64 signature over the plaintext.
        signing_algorithm: "ECDSA" or "EdDSA".
    """
    return make_message(MSG_SIGN_ONLY, {
        "plaintext":        plaintext,
        "signature":        signature,
        "signingAlgorithm": signing_algorithm,
    })


def make_error(reason: str) -> dict:
    """Construct an ERROR message."""
    return make_message(MSG_ERROR, {"reason": reason})


def make_bye() -> dict:
    """Construct a BYE message."""
    return make_message(MSG_BYE, {})


# ── Serialization ─────────────────────────────────────────────────────────────

def serialize(message: dict) -> bytes:
    """
    Serialize a message dict to length-prefixed bytes for sending over TCP.

    Format: [4-byte big-endian length][UTF-8 JSON bytes]

    Args:
        message: Message dict (from make_* functions).

    Returns:
        Bytes ready to send over a socket.
    """
    json_bytes = json.dumps(message, separators=(",", ":")).encode("utf-8")
    length     = len(json_bytes)

    if length > MAX_MSG_SIZE:
        raise ValueError(f"Message too large: {length} bytes (max {MAX_MSG_SIZE})")

    # Pack length as 4-byte big-endian unsigned int
    header = struct.pack(">I", length)
    return header + json_bytes


def deserialize(data: bytes) -> dict:
    """
    Deserialize raw bytes (without the length header) to a message dict.

    Args:
        data: JSON bytes (length header already stripped).

    Returns:
        Message dict.
    """
    return json.loads(data.decode("utf-8"))


# ── Socket send / receive ─────────────────────────────────────────────────────

def send_message(sock: socket.socket, message: dict) -> None:
    """
    Send a message over a socket with length-prefix framing.

    Args:
        sock:    Connected socket.
        message: Message dict to send.
    """
    data = serialize(message)
    sock.sendall(data)


def receive_message(sock: socket.socket) -> dict:
    """
    Receive a length-prefixed message from a socket.

    Reads exactly as many bytes as the header indicates,
    handling TCP fragmentation correctly.

    Args:
        sock: Connected socket.

    Returns:
        Message dict.

    Raises:
        ConnectionError: If the connection is closed mid-message.
        ValueError:      If the message is malformed or too large.
    """
    # Step 1: Read exactly 4 bytes for the length header
    header = _recv_exactly(sock, HEADER_SIZE)
    if not header:
        raise ConnectionError("Connection closed by peer.")

    length = struct.unpack(">I", header)[0]

    if length > MAX_MSG_SIZE:
        raise ValueError(f"Message too large: {length} bytes (max {MAX_MSG_SIZE})")

    # Step 2: Read exactly `length` bytes for the message body
    body = _recv_exactly(sock, length)
    if not body:
        raise ConnectionError("Connection closed mid-message.")

    return deserialize(body)


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly n bytes from a socket, handling fragmentation.

    TCP does not guarantee that a single recv() call returns all requested bytes.
    This function keeps reading until exactly n bytes are received.

    Args:
        sock: Connected socket.
        n:    Number of bytes to read.

    Returns:
        Exactly n bytes, or empty bytes if connection is closed.
    """
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return b""  # connection closed
        data += chunk
    return data


# ── Message validation ────────────────────────────────────────────────────────

def validate_message(message: dict, expected_type: str = None) -> bool:
    """
    Validate basic message structure.

    Args:
        message:       Message dict to validate.
        expected_type: If provided, also checks the message type matches.

    Returns:
        True if valid, False otherwise.
    """
    if not isinstance(message, dict):
        return False
    if "type" not in message or "payload" not in message:
        return False
    if expected_type and message["type"] != expected_type:
        return False
    return True


# ── Quick self-test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import threading

    print("=== Message Construction ===")
    hello = make_hello({"subject": "alice"}, ["AES-256-GCM", "ChaCha20-Poly1305"])
    print(f"HELLO:      {json.dumps(hello)[:60]}...")

    ack = make_hello_ack({"subject": "bob"}, "AES-256-GCM")
    print(f"HELLO_ACK:  {json.dumps(ack)[:60]}...")

    err = make_error("Certificate verification failed")
    print(f"ERROR:      {json.dumps(err)}")

    bye = make_bye()
    print(f"BYE:        {json.dumps(bye)}")

    print("\n=== Serialization ===")
    raw = serialize(hello)
    print(f"Serialized: {len(raw)} bytes total ({HEADER_SIZE} header + {len(raw)-HEADER_SIZE} body)")

    # Check length header
    length = struct.unpack(">I", raw[:4])[0]
    print(f"Header says body is {length} bytes ✓")

    recovered = deserialize(raw[4:])
    assert recovered == hello
    print("Deserialized correctly ✓")

    print("\n=== Socket Send/Receive ===")

    received_messages = []

    def server_thread():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 19999))
        server.listen(1)
        conn, _ = server.accept()
        # Receive multiple messages
        for _ in range(3):
            msg = receive_message(conn)
            received_messages.append(msg)
        conn.close()
        server.close()

    # Start server in background thread
    t = threading.Thread(target=server_thread)
    t.start()

    import time
    time.sleep(0.1)  # give server time to start

    # Client sends messages
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 19999))
    send_message(client, hello)
    send_message(client, ack)
    send_message(client, bye)
    client.close()

    t.join()

    assert len(received_messages) == 3
    assert received_messages[0] == hello
    assert received_messages[1] == ack
    assert received_messages[2] == bye
    print(f"Sent and received 3 messages correctly ✓")
    print(f"  Message 1 type: {received_messages[0]['type']}")
    print(f"  Message 2 type: {received_messages[1]['type']}")
    print(f"  Message 3 type: {received_messages[2]['type']}")

    print("\n=== Validation ===")
    assert validate_message(hello)
    assert validate_message(hello, MSG_HELLO)
    assert not validate_message(hello, MSG_BYE)
    assert not validate_message({"broken": "message"})
    print("Validation works correctly ✓")

    print("\nAll checks passed.")