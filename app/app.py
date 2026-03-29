import threading
import socket
import sys
from protocols.protocol import (
    send_message, receive_message, 
    make_sign_only_message, make_hello, make_hello_ack,
    MSG_HELLO, MSG_HELLO_ACK, MSG_BYE, MSG_SIGN_ONLY, MSG_MESSAGE
)

def receive_thread(sock: socket.socket, is_encrypted: bool = False):
    """Vlákno, které neustále naslouchá na socketu."""
    while True:
        try:
            msg: dict = receive_message(sock)
            m_type: str = msg['type']
            payload: str = msg['payload']

            if m_type == MSG_BYE:
                print("\n[Systém] Protějšek se odpojil.")
                break

            elif m_type == MSG_SIGN_ONLY:
                print(f"\n[Partner - PLAIN]: {payload.get('plaintext') }")
            
            elif m_type == MSG_MESSAGE:
                if is_encrypted:
                    # TADY BUDE DEŠIFROVÁNÍ
                    print(f"\n[Partner - ENCRYPTED]: (Zatím neimplementováno)")
                else:
                    print("\n[Varování] Přijata šifrovaná zpráva v nešifrovaném módu!")

            print("Moje zpráva: ", end="", flush=True)
            
        except Exception as e:
            print(f"\n[Chyba] Příjem přerušen: {e}")
            break

def run_chat(sock: socket.socket, is_encrypted: bool = False):
    """Hlavní smyčka pro odesílání zpráv."""
    # Spustíme vlákno pro příjem
    rx = threading.Thread(target=receive_thread, args=(sock, is_encrypted), daemon=True)
    rx.start()

    mode_str = "ŠIFROVANÝ" if is_encrypted else "NEŠIFROVANÝ (DEBUG)"
    print(f"--- Chat zahájen [{mode_str}] ---")

    print("--- Chat zahájen (napiš 'exit' pro ukončení) ---")
    while True:
        text = input("Moje zpráva: ")
        if text.lower() == "exit":
            send_message(sock, {"type": "BYE", "payload": {}})
            break
        
        if is_encrypted:
            # Tady později zavoláme tvou funkci pro ECIES
            # msg = make_encrypted_message(...)
            print("[Systém] Šifrování zatím není implementováno.")
        else:
            # Demo režim - jen podepsaný plaintext
            msg = make_sign_only_message(text, "debug_sig", "NONE")
            send_message(sock, msg)

def main():
    mode: str = input("Zvol režim (s = server / k = klient): ").lower()
    crypto_choice: str = input("Zapnout šifrování? (y/n): ").lower()
    is_encrypted: bool = crypto_choice == 'y'

    port: int = 12345


    if mode == 's':
        server: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(1)
        print(f"Server naslouchá na portu {port}...")
        conn, addr = server.accept()

        # Server přijme HELLO od klienta
        hello = receive_message(conn)
        print(f"[Handshake] Klient se připojil a navrhuje: {hello['payload']['supportedAlgorithms']}")
        
        # Server odpoví ACK a potvrdí, zda šifrujeme
        ack = make_hello_ack({"id": "server_cert"}, "AES-GCM" if is_encrypted else "NONE")
        send_message(conn, ack)
        
        run_chat(conn, is_encrypted)
    else:
        ip: str = input("Zadej IP adresu serveru: ")
        conn: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((ip, port))

        # Klient pošle HELLO
        algs = ["AES-GCM", "ChaCha20"] if is_encrypted else ["NONE"]
        hello = make_hello({"id": "client_cert"}, algs)
        send_message(conn, hello)

        # Klient počká na potvrzení od serveru
        ack = receive_message(conn)
        final_enc = (ack['payload']['chosenAlgorithm'] != "NONE")
        
        run_chat(conn, final_enc)

if __name__ == "__main__":
    main()