import os
import sys
import getpass
import json # Added for loading password hash

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from register import register as run_register_script
from ca_sign import sign_csr, revoke_user, list_users
from app.app import start_chat_app # We will refactor app.app.main into start_chat_app
from config import USER_KEYS_DIR, CA_KEYS_DIR, DEFAULT_SYMMETRIC_ALGO, SUPPORTED_ALGORITHMS
from crypto.keys import load_private_key, verify_password
from crypto.certificates import load_certificate, verify_certificate, get_public_key_from_cert
from config import get_ca_public_key

def handle_registration():
    """Handles the user registration process."""
    print("\n--- User Registration ---")
    run_register_script()

def handle_ca_admin():
    """Handles CA administration tasks."""
    print("\n--- CA Administration ---")
    ca_password = getpass.getpass("Enter CA admin password: ")

    while True:
        print("\nCA Admin Menu:")
        print("1. Sign a user's CSR")
        print("2. Revoke a user")
        print("3. List registered users")
        print("4. Back to Main Menu")
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
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")

def handle_login_and_chat():
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

    # Now, proceed to chat setup
    mode = input("Choose mode (s = server / c = client):").lower()
    if mode not in ['s', 'c']:
        print("Invalid mode. Please choose 's' for server or 'c' for client.")
        return

    crypto_choice = input("Enable encryption? (y/n): ").lower()
    be_encrypted = crypto_choice == 'y'

    # Call the refactored app.app function
    start_chat_app(
        username=username,
        password=password, # Password needed for decrypting private keys for signing/decryption
        mode=mode,
        be_encrypted=be_encrypted,
        user_ecdsa_priv=user_ecdsa_priv,
        user_eddsa_priv=user_eddsa_priv,
        user_ecdsa_certificate=user_ecdsa_cert,
        user_eddsa_certificate=user_eddsa_cert
    )


def main():
    """Main entry point for the ecApp."""
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
            handle_login_and_chat()
        elif choice == '3':
            handle_ca_admin()
        elif choice == '4':
            print("Exiting ecApp. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()