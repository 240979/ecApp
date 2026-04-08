import getpass
import json
import os
import sys
import config
from utils.logger import default_logger as logger, generate_log_key, load_log_key

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from register import register as run_register_script
from ca_sign import sign_csr, revoke_user, list_users
from app.app import start_chat_app # We will refactor app.app.main into start_chat_app
from config import USER_KEYS_DIR, CA_PASSWORD_HASH_FILE, SUPPORTED_ALGORITHMS
from crypto.keys import load_private_key, verify_password, hash_password # Added hash_password for completeness, verify_password is key
from crypto.certificates import load_certificate, verify_certificate
from config import get_ca_public_key

def handle_registration():
    """Handles the user registration process."""
    print("\n--- User Registration ---")
    # Check if CA admin password is set, as registration requires CA to sign CSRs
    if not os.path.exists(CA_PASSWORD_HASH_FILE):
        print(
            f"Error: CA admin password not configured. "
            f"Please run 'python config.py --generate-ca-admin-password' first "
            f"to set up the CA administrator."
        )
        # It's not strictly necessary to exit here, as registration itself doesn't need the CA password,
        # but the next step (signing the CSR) does. This provides a heads-up.
        # For now, let's allow registration but warn.
        # sys.exit(1) # Uncomment if you want to strictly enforce CA setup before user registration

    run_register_script()

def handle_ca_admin():
    """Handles CA administration tasks."""
    print("\n--- CA Administration ---")
    ca_password = getpass.getpass("Enter CA admin password: ")

    # Verify CA admin password against stored hash
    if not os.path.exists(CA_PASSWORD_HASH_FILE):
        print(f"Error: CA admin password not configured. Please run 'python config.py --generate-ca-admin-password' first.")
        return

    with open(CA_PASSWORD_HASH_FILE, "r") as f:
        stored_ca_admin_hash = json.load(f)["hash"]
    
    if not verify_password(ca_password, stored_ca_admin_hash):
        print("Error: Incorrect CA admin password.")
        return
    print("CA admin authenticated.")

    if config.LOG_ENCRYPT:
        try:
            if not os.path.exists(config.LOG_KEY_FILE):
                # First time: Generate the log key and wrap it with the CA password
                key = generate_log_key(config.LOG_KEY_FILE, ca_password)
                logger.enable_secure_logging(key)
                logger.log("LOG_SETUP", "OK", details="New log key generated and encrypted")
            else:
                # Subsequent times: Unwrap the log key
                key = load_log_key(config.LOG_KEY_FILE, ca_password)
                logger.enable_secure_logging(key)
                print("Secure logs unlocked.")
        except Exception as e:
            print(f"Warning: Admin authenticated, but secure logs failed to initialize: {e}")

    while True:
        print("\nCA Admin Menu:")
        print("1. Sign a user's CSR")
        print("2. Revoke a user")
        print("3. List registered users")
        print("4. View Security Logs (Audit Trail)")
        print("5. Back to Main Menu")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            csr_path = input("Enter path to CSR file (e.g., client/keys/<username>/csr.json): ").strip()
            if not os.path.exists(csr_path):
                print(f"Error: CSR file not found at {csr_path}")
                continue
            try:
                sign_csr(csr_path, ca_password)
                print("CSR signed successfully.")
            except SystemExit: # ca_sign.py exits on error, catch it
                pass
            except Exception as e:
                print(f"An error occurred during signing: {e}")
        elif choice == '2':
            username = input("Enter username to revoke: ").strip()
            try:
                revoke_user(username, ca_password)
                print(f"User '{username}' revoked.")
            except SystemExit:
                pass
            except Exception as e:
                print(f"An error occurred during revocation: {e}")
        elif choice == '3':
            try:
                list_users(ca_password)
            except SystemExit:
                pass
            except Exception as e:
                print(f"An error occurred while listing users: {e}")
        if choice == '4':
            entries = logger.read_logs()
            print(f"\n{'TIMESTAMP':<28} | {'EVENT':<15} | {'RESULT':<5} | {'DETAILS'}")
            print("-" * 90)
            for entry in entries:
                # Get the values, providing defaults if they are missing
                ts = entry.get("timestamp", "N/A")[:19]  # Truncate to YYYY-MM-DDTHH:MM:SS
                ev = entry.get("event", "N/A")
                rs = entry.get("result", "OK")
                dt = entry.get("details", "")  # If no details, just leave empty
                print(f"{ts:<28} | {ev:<15} | {rs:<5} | {dt}")
        elif choice == '5':
            break
        else:
            print("Invalid choice. Please try again.")

def handle_login_and_chat(debug_mode):
    """Handles user login and initiates the chat application."""
    print("\n--- User Login & Chat ---")
    username = input("Enter your username: ").strip()
    password = getpass.getpass("Enter your password: ")

    user_dir = os.path.join(USER_KEYS_DIR, username)
    if not os.path.exists(user_dir):
        print(f"Error: User '{username}' not found locally. Please register first.")
        return

    # Load password hash
    password_hash_path = os.path.join(user_dir, "password.json")
    if not os.path.exists(password_hash_path):
        print("Error: Password hash file not found. User data might be corrupted.")
        return
    
    with open(password_hash_path, "r") as f:
        stored_hash = json.load(f)
    
    if not verify_password(password, stored_hash):
        print("Error: Incorrect password.")
        return

    print(f"User '{username}' authenticated.")

    # Load user's private keys and certificates
    try:
        ecdsa_priv_path = os.path.join(user_dir, "ecdsa_priv.json")
        eddsa_priv_path = os.path.join(user_dir, "eddsa_priv.json")
        ecdsa_cert_path = os.path.join(user_dir, "ecdsa_cert.json")
        eddsa_cert_path = os.path.join(user_dir, "eddsa_cert.json")

        user_ecdsa_priv = load_private_key(ecdsa_priv_path, password)
        user_eddsa_priv = load_private_key(eddsa_priv_path, password)
        user_ecdsa_cert = load_certificate(ecdsa_cert_path)
        user_eddsa_cert = load_certificate(eddsa_cert_path)

        # Verify certificates against CA public key
        ca_public_key = get_ca_public_key()
        if not verify_certificate(user_ecdsa_cert, ca_public_key):
            print("Error: ECDSA certificate verification failed. It might be invalid or tampered.")
            return
        if not verify_certificate(user_eddsa_cert, ca_public_key):
            print("Error: EdDSA certificate verification failed. It might be invalid or tampered.")
            return

        print("User keys and certificates loaded and verified.")

    except FileNotFoundError as e:
        print(f"Error: Missing key or certificate file: {e}. Ensure you have registered and had your CSR signed.")
        return
    except ValueError as e:
        print(f"Error loading keys/certs: {e}. Incorrect password or corrupted files.")
        return
    except Exception as e:
        print(f"An unexpected error occurred during key/cert loading: {e}")
        return

    continue_logged = True
    be_encrypted = True  # default
    preferred_symmetric_algo = SUPPORTED_ALGORITHMS[0] if SUPPORTED_ALGORITHMS else "NONE" # default

    print(f"User '{username}' authenticated.")

    while continue_logged:
        print(f"\n--- Chat Menu (Logged in as: {username}) ---")
        print(f"Current Setup: Encryption={'ON' if be_encrypted else 'OFF'}, Algo={preferred_symmetric_algo}")
        print("1. Start new chat session")
        print("2. Setup (Encryption & Algorithms)")
        print("3. Logout and return to main menu")

        chat_choice = input("Select an option: ").strip()

        if chat_choice == '1':
            # Now, proceed to chat setup
            peer_ip = input("Enter peer IP (or press Enter to wait for connection): ").strip()
            peer_ip = peer_ip if peer_ip else None # If only enter is the input, better make sure that the IP is really None

            # Call the refactored app.app function
            start_chat_app(
                username=username,
                password=password, # Password needed for decrypting private keys for signing/decryption
                peer_ip=peer_ip,
                debug_mode=debug_mode,
                be_encrypted=be_encrypted,
                user_ecdsa_priv=user_ecdsa_priv,
                user_eddsa_priv=user_eddsa_priv,
                user_ecdsa_certificate=user_ecdsa_cert,
                user_eddsa_certificate=user_eddsa_cert,
                preferred_symmetric_algo=preferred_symmetric_algo
            )
        elif chat_choice == '2':
            # SETUP MENU
            print("\n--- Encryption Setup ---")

            while True:
                crypto_input = input("Enable encryption? (y/n): ").lower().strip()
                if crypto_input in ['y', 'n']:
                    be_encrypted = (crypto_input == 'y')
                    break
                else:
                    print("Invalid input. Please enter 'y' for Yes or 'n' for No.")

            if be_encrypted:
                print("\nAvailable symmetric encryption algorithms:")
                for i, algo in enumerate(SUPPORTED_ALGORITHMS):
                    print(f"{i + 1}. {algo}")

                while True:
                    try:
                        algo_index = int(input(f"Choose your preferred algorithm (1-{len(SUPPORTED_ALGORITHMS)}): ").strip()) - 1
                        if 0 <= algo_index < len(SUPPORTED_ALGORITHMS):
                            preferred_symmetric_algo = SUPPORTED_ALGORITHMS[algo_index]
                            break
                        else:
                            print("Invalid choice. Please enter a number within the range.")
                    except ValueError:
                        print("Invalid input. Enter a number.")
            else:
                preferred_symmetric_algo = "NONE"

            print("Setup updated successfully.")

        elif chat_choice == '3':
            print("Logging out...")
            continue_logged = False
        else:
            print("Invalid choice.")

def main():
    """Main entry point for the ecApp."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--debug-local", action="store_true")
    parser.add_argument("--debug-remote", action="store_true")
    args = parser.parse_args()

    debug_mode = "local" if args.debug_local else "remote" if args.debug_remote else None
    while True:
        print("\n=== ecApp Main Menu ===")
        print("1. Register a new user")
        print("2. Login and start chat")
        print("3. CA Administration")
        print("4. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            handle_registration()
        elif choice == '2':
            handle_login_and_chat(debug_mode)
        elif choice == '3':
            handle_ca_admin()
        elif choice == '4':
            print("Exiting ecApp. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()