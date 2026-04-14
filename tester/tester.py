import base64
import json
import socket
import argparse
import threading
import time
import matplotlib.pyplot as plt
import numpy as np

# Imports from team project
#
from config import DEFAULT_PORT
from crypto.ecies import (
    ecies_encrypt, ecies_decrypt, SUPPORTED_ALGORITHMS, ALGO_AES_GCM
)
from crypto.keys import (
    generate_ecdsa_keypair,
    generate_eddsa_keypair,
    public_key_to_b64
)
from crypto.signing import (
    ecdsa_sign, ecdsa_verify,
    eddsa_sign, eddsa_verify
)
from protocols.protocol import (
    send_message, receive_message,
    make_sign_only_message, make_encrypted_message
)
from utils.logger import default_logger as logger


def get_key_size_bytes(public_key) -> int:
    """Helper to determine the actual public key size in bytes from DER format."""
    b64_key = public_key_to_b64(public_key)
    return len(base64.b64decode(b64_key))

def benchmark_algorithms():
    print("\n" + "="*60)
    print(" ALGORITHM BENCHMARK (ECDSA vs EdDSA)")
    print("="*60)
    
    message = b"Test message for performance measurement and signature length."
    iterations = 500 # Number of repetitions for more accurate average time

    # Store results for plotting
    results = {
        "ECDSA": {}, "EdDSA": {}, "ECIES": {"encryption_times": {}, "decryption_times": {}, "bundle_sizes": {}}
    }
    
    # --- 1. ECDSA Benchmark ---
    print("\n--- ECDSA (Curve SECP256R1) ---")
    
    # Key Generation
    start = time.perf_counter()
    for _ in range(iterations):
        ecdsa_priv, ecdsa_pub = generate_ecdsa_keypair()
    ecdsa_keygen_time = (time.perf_counter() - start) / iterations
    
    # Key Size
    ecdsa_pub_size = get_key_size_bytes(ecdsa_pub)
    
    # Signing Speed
    start = time.perf_counter()
    for _ in range(iterations):
        ecdsa_sig = ecdsa_sign(ecdsa_priv, message)
    ecdsa_sign_time = (time.perf_counter() - start) / iterations
    
    # Verification Speed
    start = time.perf_counter()
    for _ in range(iterations):
        ecdsa_verify(ecdsa_pub, message, ecdsa_sig)
    ecdsa_verify_time = (time.perf_counter() - start) / iterations

    print(f"Public Key Size:      {ecdsa_pub_size} bytes")
    print(f"Signature Size:       {len(ecdsa_sig)} bytes")
    print(f"Avg Keygen Time:      {ecdsa_keygen_time * 1000:.3f} ms")
    print(f"Avg Signing Time:     {ecdsa_sign_time * 1000:.3f} ms")
    print(f"Avg Verification Time: {ecdsa_verify_time * 1000:.3f} ms")

    results["ECDSA"]["keygen_time"] = ecdsa_keygen_time * 1000
    results["ECDSA"]["sign_time"] = ecdsa_sign_time * 1000
    results["ECDSA"]["verify_time"] = ecdsa_verify_time * 1000
    results["ECDSA"]["pub_key_size"] = ecdsa_pub_size
    results["ECDSA"]["sig_size"] = len(ecdsa_sig)



    # --- 2. EdDSA Benchmark ---
    print("\n--- EdDSA (Curve Ed25519) ---")
    
    # Key Generation
    start = time.perf_counter()
    for _ in range(iterations):
        eddsa_priv, eddsa_pub = generate_eddsa_keypair()
    eddsa_keygen_time = (time.perf_counter() - start) / iterations
    
    # Key Size
    eddsa_pub_size = get_key_size_bytes(eddsa_pub)
    
    # Signing Speed
    start = time.perf_counter()
    for _ in range(iterations):
        eddsa_sig = eddsa_sign(eddsa_priv, message)
    eddsa_sign_time = (time.perf_counter() - start) / iterations
    
    # Verification Speed
    start = time.perf_counter()
    for _ in range(iterations):
        eddsa_verify(eddsa_pub, message, eddsa_sig)
    eddsa_verify_time = (time.perf_counter() - start) / iterations

    print(f"Public Key Size:      {eddsa_pub_size} bytes")
    print(f"Signature Size:       {len(eddsa_sig)} bytes")
    print(f"Avg Keygen Time:      {eddsa_keygen_time * 1000:.3f} ms")
    print(f"Avg Signing Time:     {eddsa_sign_time * 1000:.3f} ms")
    print(f"Avg Verification Time: {eddsa_verify_time * 1000:.3f} ms")
    
    results["EdDSA"]["keygen_time"] = eddsa_keygen_time * 1000
    results["EdDSA"]["sign_time"] = eddsa_sign_time * 1000
    results["EdDSA"]["verify_time"] = eddsa_verify_time * 1000
    results["EdDSA"]["pub_key_size"] = eddsa_pub_size
    results["EdDSA"]["sig_size"] = len(eddsa_sig)

# --- 3. ECIES Benchmark ---
    print("\n--- ECIES (Hybrid Encryption via SECP256R1) ---")
    print("Note: ECIES generates an ephemeral key and performs ECDH on EVERY encryption.")
    
    recipient_priv, recipient_pub = generate_ecdsa_keypair()
    
    for algo in SUPPORTED_ALGORITHMS:
        print(f"\n  [ Backend: {algo} ]")
        
        start = time.perf_counter()
        for _ in range(iterations):
            bundle = ecies_encrypt(recipient_pub, message, algorithm=algo)
        enc_time = (time.perf_counter() - start) / iterations
        
        start = time.perf_counter()
        for _ in range(iterations):
            ecies_decrypt(recipient_priv, bundle)
        dec_time = (time.perf_counter() - start) / iterations
        
        bundle_json_str = json.dumps(bundle)
        bundle_size = len(bundle_json_str.encode('utf-8'))
        
        print(f"  Total Bundle Size:     {bundle_size} bytes (JSON serialized)")
        print(f"  Avg Encryption Time:   {enc_time * 1000:.3f} ms")
        print(f"  Avg Decryption Time:   {dec_time * 1000:.3f} ms")

        results["ECIES"]["encryption_times"][algo] = enc_time * 1000
        results["ECIES"]["decryption_times"][algo] = dec_time * 1000
        results["ECIES"]["bundle_sizes"][algo] = bundle_size

    return results

def plot_benchmark_results(results):
    print("\n" + "="*60)
    print(" GENERATING VISUALIZATIONS")
    print("="*60)

    # --- ECDSA vs EdDSA Comparison Plots ---
    labels = ['ECDSA', 'EdDSA']
    x = np.arange(len(labels))
    width = 0.35

    # Key Generation Time
    fig1, ax1 = plt.subplots(figsize=(8, 5))
    keygen_times = [results['ECDSA']['keygen_time'], results['EdDSA']['keygen_time']]
    ax1.bar(x, keygen_times, width, label='Keygen Time')
    ax1.set_ylabel('Time (ms)')
    ax1.set_title('Average Key Generation Time')
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.legend()
    fig1.tight_layout()

    # Public Key Size
    fig2, ax2 = plt.subplots(figsize=(8, 5))
    pub_key_sizes = [results['ECDSA']['pub_key_size'], results['EdDSA']['pub_key_size']]
    ax2.bar(x, pub_key_sizes, width, label='Public Key Size')
    ax2.set_ylabel('Size (bytes)')
    ax2.set_title('Public Key Size Comparison')
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels)
    ax2.legend()
    fig2.tight_layout()

    # Signature Size
    fig3, ax3 = plt.subplots(figsize=(8, 5))
    sig_sizes = [results['ECDSA']['sig_size'], results['EdDSA']['sig_size']]
    ax3.bar(x, sig_sizes, width, label='Signature Size')
    ax3.set_ylabel('Size (bytes)')
    ax3.set_title('Signature Size Comparison')
    ax3.set_xticks(x)
    ax3.set_xticklabels(labels)
    ax3.legend()
    fig3.tight_layout()

    # --- ECIES Performance Plots ---
    ecies_algos = list(results['ECIES']['encryption_times'].keys())
    x_ecies = np.arange(len(ecies_algos))

    # ECIES Encryption/Decryption Times
    fig4, ax4 = plt.subplots(figsize=(10, 6))
    enc_times = [results['ECIES']['encryption_times'][algo] for algo in ecies_algos]
    dec_times = [results['ECIES']['decryption_times'][algo] for algo in ecies_algos]
    ax4.bar(x_ecies - width/2, enc_times, width, label='Encryption Time')
    ax4.bar(x_ecies + width/2, dec_times, width, label='Decryption Time')
    ax4.set_ylabel('Time (ms)')
    ax4.set_title('ECIES Encryption and Decryption Times by Symmetric Algorithm')
    ax4.set_xticks(x_ecies)
    ax4.set_xticklabels(ecies_algos)
    ax4.legend()
    fig4.tight_layout()

    plt.show()

def demonstrate_failures():
    print("\n" + "="*60)
    print(" FAILURE DEMONSTRATION (SECURITY TESTS)")
    print("="*60)
    
    message = b"Top secret communication between Alice and Bob."
    
    # --- 1. ECDSA Failures ---
    print("\n--- 1. ECDSA Signatures (SECP256R1) ---")
    alice_ecdsa_priv, alice_ecdsa_pub = generate_ecdsa_keypair()
    eva_ecdsa_priv, eva_ecdsa_pub = generate_ecdsa_keypair()
    valid_ecdsa_sig = ecdsa_sign(alice_ecdsa_priv, message)
    
    print("[Test 1.1] Altering one byte in ECDSA signature (Data-in-transit modification)")
    tampered_ecdsa = bytearray(valid_ecdsa_sig)
    # Pozor: ECDSA podpisy používají ASN.1 DER kódování. Změna bajtu může rozbít samotnou 
    # strukturu podpisu, takže ověření může vyhodit přímo výjimku, nebo prostě vrátit False.
    tampered_ecdsa[10] ^= 0xFF
    try:
        if not ecdsa_verify(alice_ecdsa_pub, message, bytes(tampered_ecdsa)):
            print("-> SUCCESS: ecdsa_verify returned False. Tampered ECDSA signature was rejected.")
            logger.log_tamper("ECDSA signature byte flipped")
    except Exception as e:
        print(f"-> SUCCESS: ecdsa_verify failed with exception (likely invalid DER structure): {type(e).__name__}")

    print("[Test 1.2] Verifying valid ECDSA signature with a different public key (Identity spoofing)")
    if not ecdsa_verify(eva_ecdsa_pub, message, valid_ecdsa_sig):
        print("-> SUCCESS: ecdsa_verify returned False. Eva's key cannot verify Alice's ECDSA signature.")
        logger.log_auth_fail("Wrong public key used for ECDSA verify")

    # --- 2. EdDSA Failures ---
    print("\n--- 2. EdDSA Signatures (Ed25519) ---")
    alice_eddsa_priv, alice_eddsa_pub = generate_eddsa_keypair()
    eva_eddsa_priv, eva_eddsa_pub = generate_eddsa_keypair()
    valid_eddsa_sig = eddsa_sign(alice_eddsa_priv, message)
    
    print("[Test 2.1] Altering one byte in EdDSA signature (Data-in-transit modification)")
    tampered_eddsa = bytearray(valid_eddsa_sig)
    tampered_eddsa[10] ^= 0xFF
    if not eddsa_verify(alice_eddsa_pub, message, bytes(tampered_eddsa)):
        print("-> SUCCESS: eddsa_verify returned False. Tampered signature was rejected.")
        logger.log_tamper("EdDSA signature byte flipped")

    print("[Test 2.2] Verifying valid EdDSA signature with a different public key (Identity spoofing)")
    if not eddsa_verify(eva_eddsa_pub, message, valid_eddsa_sig):
        print("-> SUCCESS: eddsa_verify returned False. Eva's key cannot verify Alice's signature.")
        logger.log_tamper("EdDSA signature byte flipped")

   # --- 3. ECIES Failures ---
    print("\n--- 3. ECIES Encryption (AEAD Integrity) ---")
    print("[Test 3.1] Modifying ECIES ciphertext in memory")
    
    # Zašifrujeme zprávu pomocí ECIES a AES-GCM backendu
    ecies_bundle = ecies_encrypt(alice_ecdsa_pub, message, algorithm=ALGO_AES_GCM)
    
    # Útočník v paměti manipuluje se zašifrovanými daty v ECIES bundlu
    ct_bytes = bytearray(base64.b64decode(ecies_bundle["encrypted"]["ciphertext"]))
    ct_bytes[-1] ^= 0xFF  # Záměrně poškodíme poslední bajt (typicky součást MAC tagu)
    ecies_bundle["encrypted"]["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode('utf-8')
    
    try:
        ecies_decrypt(alice_ecdsa_priv, ecies_bundle)
        print("-> FAILURE: ECIES decrypted tampered data! (This should not happen)")
    except Exception as e:
        print(f"-> SUCCESS: ECIES decryption failed as expected! Caught exception: {type(e).__name__}")
        logger.log_decrypt(ALGO_AES_GCM, len(ct_bytes), success=False)

# --- NETWORK SIMULATION ---

def network_server_thread(server_ecdsa_priv):
    """Simulates the receiving end of the application."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", DEFAULT_PORT))
    server.listen(1)
    
    print(f"[Server] Listening on 127.0.0.1:{DEFAULT_PORT} (Check Wireshark now!)...")
    conn, addr = server.accept()
    print(f"[Server] Connection established with {addr}")
    
    try:
        # 1. Receive Unencrypted
        msg1 = receive_message(conn)
        print("[Server] Received Message 1 (Unencrypted):")
        print(f"         Type: {msg1['type']}")
        print(f"         Plaintext: {msg1['payload']['plaintext']}")
        
        # 2. Receive Encrypted (Successful)
        msg2 = receive_message(conn)
        print("[Server] Received Message 2 (Encrypted):")
        print(f"         Type: {msg2['type']}")
        

        # Decrypting Message 2 ECIES Bundle
        ecies_bundle2 = msg2['payload']['eciesBundle']
        decrypted_msg = ecies_decrypt(server_ecdsa_priv, ecies_bundle2)
        print(f"         -> Successfully decrypted: {decrypted_msg.decode('utf-8')}")
        logger.log_decrypt("ECIES", len(decrypted_msg), success=True)

        # 3. Receive Encrypted (Tampered)
        msg3 = receive_message(conn)
        print("\n[Server] Received Message 3 (ECIES Encrypted, Tampered in transit):")
        logger.log_tamper("ECIES ciphertext authentication failed")
        ecies_bundle3 = msg3['payload']['eciesBundle']
        
        try:
            print("         Attempting ECIES decryption...")
            ecies_decrypt(server_ecdsa_priv, ecies_bundle3)
            print("         -> FAILURE: Decrypted tampered data!")
        except Exception as e:
            # ECIES will throw an exception (like InvalidTag or ValueError) depending on the backend used
            print(f"         -> SUCCESS (Expected Error): Decryption failed! Cryptography exception caught: {e}")
            logger.log_tamper("ECIES ciphertext authentication failed")

    except Exception as e:
        print(f"[Server] Error: {e}")
    finally:
        conn.close()
        server.close()
        print("[Server] Connection closed.")

def simulate_network_communication():
    print("\n" + "="*60)
    print(" NETWORK COMMUNICATION SIMULATION (WIRESHARK TEST)")
    print("="*60)
    
    # Shared session key for the simulation
    client_eddsa_priv, _ = generate_eddsa_keypair() # For signing
    server_ecdsa_priv, server_ecdsa_pub = generate_ecdsa_keypair() # For ECIES receiving
    logger.log_key_gen("ECDSA-P256")
    logger.log_key_gen("Ed25519")
    session_symmetric_algo = ALGO_AES_GCM # Simulating handshake result
    
    # Start server in background
    server_thread = threading.Thread(target=network_server_thread, args=(server_ecdsa_priv,))
    server_thread.start()
    
    # Give server a moment to start listening
    time.sleep(0.5)
    
    # --- Client Side (Sender) ---
    print(f"[Client] Connecting to 127.0.0.1:{DEFAULT_PORT}...")
    client_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_conn.connect(("127.0.0.1", DEFAULT_PORT))
        time.sleep(0.5)

        # Message 1: Unencrypted (Visible in Wireshark)
        plaintext = "Hello Bob! This is in PLAINTEXT. You can read me in Wireshark!"
        sig1 = eddsa_sign(client_eddsa_priv, plaintext.encode('utf-8'))
        msg1 = make_sign_only_message(plaintext, base64.b64encode(sig1).decode('utf-8'), "EdDSA")
        print("")
        print("\n[Client] Sending unencrypted message...")
        send_message(client_conn, msg1)
        time.sleep(1) # Sleep to separate packets in Wireshark
        
        # Message 2: Encrypted via ECIES (Hidden in Wireshark)
        secret_text = b"Secret launch codes: 12345. Wireshark cannot see this!"
        
        # Use ECIES just like in your run_chat function
        ecies_bundle2 = ecies_encrypt(server_ecdsa_pub, secret_text, algorithm=session_symmetric_algo)
        sig2 = eddsa_sign(client_eddsa_priv, json.dumps(ecies_bundle2, separators=(",", ":")).encode('utf-8'))
        msg2 = make_encrypted_message(ecies_bundle2, base64.b64encode(sig2).decode('utf-8'), "EdDSA")
        
        print("\n[Client] Sending ENCRYPTED message...")
        send_message(client_conn, msg2)
        time.sleep(1)
        
        # Message 3: Encrypted via ECIES but TAMPERED (We modify bytes before sending)
        secret_text3 = b"I am a valid encrypted message, but an attacker will change me."
        
        ecies_bundle3 = ecies_encrypt(server_ecdsa_pub, secret_text3, algorithm=session_symmetric_algo)
        
        # MALICIOUS ACTION: Attacker intercepts the ECIES bundle and flips a bit in the ciphertext
        ct_bytes = bytearray(base64.b64decode(ecies_bundle3["encrypted"]["ciphertext"]))
        ct_bytes[5] ^= 0xFF # Flip a bit
        ecies_bundle3["encrypted"]["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode('utf-8')
        
        # Sign the tampered bundle to ensure it gets to the decryption phase on the server
        # (If we didn't sign it, the server would reject it at the verification step, but we want to show ECIES failing)
        sig3 = eddsa_sign(client_eddsa_priv, json.dumps(ecies_bundle3, separators=(",", ":")).encode('utf-8'))
        msg3 = make_encrypted_message(ecies_bundle3, base64.b64encode(sig3).decode('utf-8'), "EdDSA")
        
        print("\n[Client] Sending ENCRYPTED but TAMPERED message...")
        send_message(client_conn, msg3)
        
    except Exception as e:
        print(f"\n[Client] Error: {e}")
    finally:
        client_conn.close()
        server_thread.join()
        print("\n[Client] Done.")


def main():
    parser = argparse.ArgumentParser(description="ecApp Cryptographic Tester Tool")
    parser.add_argument("--plot", action="store_true", help="Generate and display plots for benchmarks.")
    args = parser.parse_args()

    while True:
        print("\n=== CRYPTO ALGORITHM TEST TOOL ===")
        print("1. Algorithm Benchmarks (Speed, Size, Performance)")
        print("2. Demonstrate Security Failures (Integrity/Identity attacks)")
        print("3. Simulate Network Communication (Wireshark Capture Test via Loopback)")
        print("4. Exit")
        
        choice = input("Select action (1-4): ")
        
        if choice == '1':
            benchmark_results = benchmark_algorithms()
            if args.plot:
                plot_benchmark_results(benchmark_results)
        elif choice == '2':
            demonstrate_failures()
        elif choice == '3':
            simulate_network_communication()
        elif choice == '4':
            print("Exiting tester tool.")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()