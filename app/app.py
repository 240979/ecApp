# general-known imports
import json  # Added for json.dumps in signing ECIES bundle
import socket
import threading

# team imports
from config import SUPPORTED_ALGORITHMS, DEFAULT_SYMMETRIC_ALGO, get_ca_public_key
from crypto.certificates import verify_certificate, get_public_key_from_cert
from crypto.ecies import ecies_encrypt, ecies_decrypt
from crypto.signing import eddsa_sign, eddsa_verify, signature_to_b64, signature_from_b64
from protocols.protocol import (
    send_message, receive_message, make_error, make_encrypted_message,
    make_sign_only_message, make_hello, make_hello_ack,
    MSG_BYE, MSG_SIGN_ONLY, MSG_MESSAGE, make_bye
)

# Global variables to hold session-specific crypto objects
# These will be set during the handshake
peer_ecdsa_pub_key = None
peer_eddsa_pub_key = None
session_symmetric_algo = None

# User's own crypto objects (passed from main_app.py)
user_ecdsa_priv_key = None
user_eddsa_priv_key = None
user_ecdsa_cert = None
user_eddsa_cert = None

chat_active_event = threading.Event()


def receive_thread(sock: socket.socket, is_encrypted: bool = False):
    """Thread that constantly listens on the socket."""
    while chat_active_event.is_set(): # Loop as long as chat is active
        try:
            msg: dict = receive_message(sock) # This can block
            m_type: str = msg['type']
            payload: str = msg['payload']

            if m_type == MSG_BYE:
                print("\n[System] Peer disconnected.")
                break

            elif m_type == MSG_SIGN_ONLY:
                # For MSG_SIGN_ONLY, we expect plaintext and a signature
                plaintext = payload.get('plaintext')
                signature_b64 = payload.get('signature')
                signing_algo = payload.get('signingAlgorithm')

                if peer_eddsa_pub_key and signing_algo == "EdDSA": # Assuming EdDSA for SIGN_ONLY
                    if eddsa_verify(peer_eddsa_pub_key, plaintext.encode('utf-8'), signature_from_b64(signature_b64)):
                        print(f"\n[Partner - PLAIN, VERIFIED]: {plaintext}")
                    else:
                        print(f"\n[Partner - PLAIN, FAILED VERIFICATION]: {plaintext}")
                else:
                    print(f"\n[Partner - PLAIN]: {plaintext}")
            
            elif m_type == MSG_MESSAGE:
                if is_encrypted:
                    # DECRYPTION WILL BE HERE
                    try:
                        ecies_bundle = payload.get('eciesBundle')
                        signature_b64 = payload.get('signature')
                        signing_algo = payload.get('signingAlgorithm')

                        # Verify signature over the ECIES bundle
                        # The actual plaintext is inside the bundle, so we sign the bundle itself
                        if peer_eddsa_pub_key and signing_algo == "EdDSA" and \
                           eddsa_verify(peer_eddsa_pub_key, json.dumps(ecies_bundle, separators=(",", ":")).encode('utf-8'), signature_from_b64(signature_b64)):
                            
                            # Decrypt the message
                            decrypted_bytes = ecies_decrypt(user_ecdsa_priv_key, ecies_bundle)
                            print(f"\n[Partner - ENCRYPTED, VERIFIED]: {decrypted_bytes.decode('utf-8')}")
                        else:
                            print(f"\n[Partner - ENCRYPTED, FAILED VERIFICATION]: (Could not verify signature or no peer key) {ecies_bundle}")

                    except Exception as decrypt_e:
                        print(f"\n[Partner - ENCRYPTED, DECRYPTION FAILED]: {decrypt_e}")
                else:
                    print("\n[Warning] Encrypted message received in unencrypted mode!")

        except ConnectionError:
            print("\n[System] Peer disconnected unexpectedly.")
            break
        except Exception as e: # Catch other unexpected errors
            print(f"\n[Error] Reception interrupted due to unexpected error: {type(e).__name__}: {e}")
            break
    
    # Signal the main thread that this thread is done
    chat_active_event.clear() # Ensure event is cleared on thread exit
    print("[System] Receive thread terminated.")

def run_chat(sock: socket.socket, is_encrypted: bool = False):
    """Main loop for sending messages."""
    global chat_active_event

    mode_str = "ENCRYPTED" if is_encrypted else "UNENCRYPTED (DEBUG)"
    print(f"--- Chat started [{mode_str}] ---")
    print("--- Chat started (type 'exit' to quit) ---")

    chat_active_event.set() # Mark chat as active ONCE, BEFORE starting the thread
    # Start the receiving thread ONCE per chat session
    rx = threading.Thread(target=receive_thread, args=(sock, is_encrypted), daemon=True)
    rx.start()

    try:
        while chat_active_event.is_set(): # Loop as long as chat is active
            try:
                text = input("My message: ") # This can block
                # If chat was terminated by receive_thread while input() was blocking,
                # we should break immediately after input() returns.
                if not chat_active_event.is_set():
                    break
            except EOFError: # Handle Ctrl+D
                print("\n[System] EOF detected. Exiting chat.")
                text = "exit" # Simulate exit command
            except KeyboardInterrupt: # Handle Ctrl+C
                print("\n[System] Keyboard interrupt detected. Exiting chat.")
                text = "exit" # Simulate exit command

            if text.lower() == "exit":
                try:
                    send_message(sock, make_bye())
                except Exception as e:
                    print(f"[System Warning] Failed to send BYE message: {e}")
                break
            
            # Convert text to bytes for crypto operations
            message_bytes = text.encode('utf-8')

            if is_encrypted:
                if not peer_ecdsa_pub_key or not user_eddsa_priv_key or not session_symmetric_algo:
                    print("[System Error] Cannot send encrypted message: peer public key, user private key, or symmetric algorithm not established.")
                    continue
                
                try:
                    # Encrypt the message using ECIES
                    ecies_bundle = ecies_encrypt(peer_ecdsa_pub_key, message_bytes, algorithm=session_symmetric_algo)
                    
                    # Sign the ECIES bundle (not the plaintext)
                    signature = eddsa_sign(user_eddsa_priv_key, json.dumps(ecies_bundle, separators=(",", ":")).encode('utf-8'))
                    signature_b64 = signature_to_b64(signature)

                    msg = make_encrypted_message(ecies_bundle, signature_b64, "EdDSA") # Assuming EdDSA for signing
                    send_message(sock, msg)
                    print(f"[Me - ENCRYPTED]: {text}")

                except Exception as e:
                    print(f"[System Error] Failed to encrypt or sign message: {e}")
                    # Fallback or error handling
                    msg = make_sign_only_message(text, "ERROR_SIG", "NONE") # Send unencrypted with error
                    send_message(sock, msg)

            else:
                # Demo mode - signed plaintext only
                if not user_eddsa_priv_key:
                    print("[System Error] Cannot sign message: user private key not loaded.")
                    signature_b64 = "NO_KEY_SIG"
                else:
                    signature = eddsa_sign(user_eddsa_priv_key, message_bytes)
                    signature_b64 = signature_to_b64(signature)

                msg = make_sign_only_message(text, signature_b64, "EdDSA") # Assuming EdDSA for signing
                send_message(sock, msg)
                print(f"[Me - PLAIN]: {text}")
        chat_active_event.clear() # Ensure event is cleared even if an error occurs
        rx.join(timeout=1) # Give receive thread a moment to clean up
        print("[System] Chat session ended.")
        sock.close() # Close the connection socket here
    except Exception as e:
        print(f"[System Error] An unexpected error occurred in run_chat: {e}")
    finally:
        chat_active_event.clear() # Ensure event is cleared even if an error occurs
        rx.join(timeout=1) # Give receive thread a moment to clean up


# The 'server' socket is closed by the server branch.
# The 'conn' socket is closed by run_chat.
from network.peer import establish_connection


def start_chat_app(
        username: str,
        password: str,
        be_encrypted: bool,
        user_ecdsa_priv,
        user_eddsa_priv,
        user_ecdsa_certificate: dict,
        user_eddsa_certificate: dict,
        peer_ip: str = None,  # Added for P2P routing
        debug_mode: str = None  # Added for P2P local debugging
):
    """
    Starts the chat application with pre-loaded user credentials over a P2P connection.
    """
    global user_ecdsa_priv_key, user_eddsa_priv_key, user_ecdsa_cert, user_eddsa_cert
    global peer_ecdsa_pub_key, peer_eddsa_pub_key, session_symmetric_algo

    user_ecdsa_priv_key = user_ecdsa_priv
    user_eddsa_priv_key = user_eddsa_priv
    user_ecdsa_cert = user_ecdsa_certificate
    user_eddsa_cert = user_eddsa_certificate

    ca_public_key = get_ca_public_key()

    print("Establishing P2P connection...")
    try:
        conn = establish_connection(peer_ip, debug_mode)
    except Exception as e:
        print(f"Failed to establish connection: {e}")
        return

    try:
        # --- HANDSHAKE PHASE ---

        # If no IP was provided, we acted as the passive listener.
        # We act as the handshake Responder (wait for HELLO, send ACK).
        if not peer_ip:
            hello = receive_message(conn)
            peer_ecdsa_hello_cert = hello['payload']['ecdsaCertificate']
            peer_eddsa_hello_cert = hello['payload']['eddsaCertificate']
            peer_supported_algs = hello['payload']['supportedAlgorithms']

            if not verify_certificate(peer_ecdsa_hello_cert, ca_public_key):
                print("[Handshake Error] Peer ECDSA certificate verification failed. Disconnecting.")
                send_message(conn, make_error("Peer ECDSA certificate invalid."))
                return
            if not verify_certificate(peer_eddsa_hello_cert, ca_public_key):
                print("[Handshake Error] Peer EdDSA certificate verification failed. Disconnecting.")
                send_message(conn, make_error("Peer EdDSA certificate invalid."))
                return

            peer_ecdsa_pub_key = get_public_key_from_cert(peer_ecdsa_hello_cert)
            peer_eddsa_pub_key = get_public_key_from_cert(peer_eddsa_hello_cert)

            print(
                f"[Handshake] Peer '{peer_ecdsa_hello_cert['subject']}' connected and proposes: {peer_supported_algs}")

            if be_encrypted and DEFAULT_SYMMETRIC_ALGO in peer_supported_algs:
                session_symmetric_algo = DEFAULT_SYMMETRIC_ALGO
            else:
                session_symmetric_algo = "NONE"

            ack = make_hello_ack(user_ecdsa_cert, user_eddsa_cert, session_symmetric_algo)
            send_message(conn, ack)

            run_chat(conn, session_symmetric_algo != "NONE")

        # If an IP was provided, we actively connected.
        # We act as the handshake Initiator (send HELLO, wait for ACK).
        else:
            client_supported_algs = SUPPORTED_ALGORITHMS if be_encrypted else ["NONE"]
            hello = make_hello(user_ecdsa_cert, user_eddsa_cert, client_supported_algs)
            send_message(conn, hello)

            ack = receive_message(conn)
            peer_ecdsa_ack_cert = ack['payload']['ecdsaCertificate']
            peer_eddsa_ack_cert = ack['payload']['eddsaCertificate']
            chosen_algorithm = ack['payload']['chosenAlgorithm']

            if not verify_certificate(peer_ecdsa_ack_cert, ca_public_key):
                print("[Handshake Error] Peer ECDSA certificate verification failed. Disconnecting.")
                send_message(conn, make_error("Peer ECDSA certificate invalid."))
                return
            if not verify_certificate(peer_eddsa_ack_cert, ca_public_key):
                print("[Handshake Error] Peer EdDSA certificate verification failed. Disconnecting.")
                send_message(conn, make_error("Peer EdDSA certificate invalid."))
                return

            peer_ecdsa_pub_key = get_public_key_from_cert(peer_ecdsa_ack_cert)
            peer_eddsa_pub_key = get_public_key_from_cert(peer_eddsa_ack_cert)

            print(
                f"[Handshake] Peer '{peer_ecdsa_ack_cert['subject']}' acknowledged with algorithm: {chosen_algorithm}")

            if chosen_algorithm != "NONE":
                session_symmetric_algo = chosen_algorithm
                final_enc = True
            else:
                session_symmetric_algo = "NONE"
                final_enc = False

            run_chat(conn, final_enc)

    finally:
        # Ensures the P2P connection socket is cleanly closed regardless of crashes or normal exits
        if conn:
            conn.close()