# general-known imports
import threading
import socket
import sys

# team imports
from protocols.protocol import (
    send_message, receive_message, 
    make_sign_only_message, make_hello, make_hello_ack,
    MSG_HELLO, MSG_HELLO_ACK, MSG_BYE, MSG_SIGN_ONLY, MSG_MESSAGE
)
from config import DEFAULT_PORT, ALGO_AES_GCM, ALGO_CHACHA20, ALGO_AES_CBC_HMAC, SUPPORTED_ALGORITHMS

def receive_thread(sock: socket.socket, is_encrypted: bool = False):
    """Thread that constantly listens on the socket."""
    while True:
        try:
            msg: dict = receive_message(sock)
            m_type: str = msg['type']
            payload: str = msg['payload']

            if m_type == MSG_BYE:
                print("\n[System] Peer disconnected.")
                break

            elif m_type == MSG_SIGN_ONLY:
                print(f"\n[Partner - PLAIN]: {payload.get('plaintext') }")
            
            elif m_type == MSG_MESSAGE:
                if is_encrypted:

                    # DECRYPTION WILL BE HERE

                    print(f"\n[Partner - ENCRYPTED]: (Not implemented yet)")
                else:
                    print("\n[Warning] Encrypted message received in unencrypted mode!")

            print("My message: ", end="", flush=True)
            
        except Exception as e:
            print(f"\n[Error] Reception interrupted: {e}")
            break

def run_chat(sock: socket.socket, is_encrypted: bool = False):
    """Main loop for sending messages."""
    # Start the receiving thread
    rx = threading.Thread(target=receive_thread, args=(sock, is_encrypted), daemon=True)
    rx.start()

    mode_str = "ENCRYPTED" if is_encrypted else "UNENCRYPTED (DEBUG)"
    print(f"--- Chat started [{mode_str}] ---")

    print("--- Chat started (type 'exit' to quit) ---")
    while True:
        text = input("My message: ")
        if text.lower() == "exit":
            send_message(sock, {"type": "BYE", "payload": {}})
            break
        
        if is_encrypted:

            # Later we will call your ECIES function here
            # msg = make_encrypted_message(...)

            print("[System] Encryption not implemented yet.")
        else:
            # Demo mode - signed plaintext only
            msg = make_sign_only_message(text, "debug_sig", "NONE")
            send_message(sock, msg)

def main():
    mode: str = input("Choose mode (s = server / c = client):").lower()
    crypto_choice: str = input("Enable encryption? (y/n): ").lower()
    be_encrypted: bool = crypto_choice == 'y'


    if mode == 's':
        server: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", DEFAULT_PORT))
        server.listen(1)
        print(f"Server listening on port {DEFAULT_PORT}...")
        conn, addr = server.accept()

        # Server receives HELLO from the client
        hello = receive_message(conn)
        print(f"[Handshake] Client connected and proposes: {hello['payload']['supportedAlgorithms']}")
        
        # Server responds with ACK and confirms encryption
        ack = make_hello_ack({"id": "server_cert"}, "AES-GCM" if be_encrypted else "NONE")
        send_message(conn, ack)
        
        run_chat(conn, be_encrypted)
    else:
        ip: str = input("Enter server IP address: ")
        conn: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((ip, DEFAULT_PORT))

        # Client sends HELLO
        algs = SUPPORTED_ALGORITHMS if be_encrypted else ["NONE"]
        hello = make_hello({"id": "client_cert"}, algs)
        send_message(conn, hello)

        # Client waits for acknowledgment from the server
        ack = receive_message(conn)
        final_enc = (ack['payload']['chosenAlgorithm'] != "NONE")
        
        run_chat(conn, final_enc)

if __name__ == "__main__":
    main()