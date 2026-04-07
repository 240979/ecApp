"""
network/peer.py

P2P connection management for ecApp.

In true P2P, both peers:
    - Listen on their port for incoming connections
    - Connect outward to the other peer's port

There is no "server" or "client" — just two peers.
The only asymmetry is who initiates the connection first.

Normal mode (two machines):
    Both peers run on port 25519.
    Alice enters Bob's IP → Alice connects to Bob:25519
    Bob's listener accepts → connection established

Debug mode (two instances on same machine):
    --debug-local   listens on 25518, connects to localhost:25519
    --debug-remote  listens on 25519, connects to localhost:25518

Usage:
    python main_app.py                  # normal mode
    python main_app.py --debug-local    # debug: local side
    python main_app.py --debug-remote   # debug: remote side
"""

import socket
import threading
import time
from typing import Optional

from config import DEFAULT_PORT

# Debug ports
DEBUG_LOCAL_PORT  = DEFAULT_PORT - 1   # 25518
DEBUG_REMOTE_PORT = DEFAULT_PORT       # 25519

# How long to wait for outgoing connection before giving up (seconds)
CONNECT_TIMEOUT = 30


class PeerConnection:
    """
    Manages a P2P connection between two peers.

    Handles both the outgoing connection attempt and the incoming
    listener simultaneously — whoever connects first wins.
    """

    def __init__(self, listen_port: int, connect_port: int):
        """
        Args:
            listen_port:  Port to listen on for incoming connections.
            connect_port: Port to connect to on the remote peer.
        """
        self.is_initiator = False
        self.listen_port  = listen_port
        self.connect_port = connect_port
        self.sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._connected = threading.Event()

    def connect(self, peer_ip: Optional[str] = None) -> tuple[socket.socket, bool]:
        """
        Establish a P2P connection.

        If peer_ip is provided: attempt outgoing connection while also listening.
        If peer_ip is None: just listen for incoming connection.

        Args:
            peer_ip: IP address of the peer to connect to.
                     None means wait for incoming connection only.

        Returns:
            Connected socket.
        """
        threads = []

        # Always start listener
        listener_thread = threading.Thread(
            target=self._listen,
            daemon=True
        )
        listener_thread.start()
        threads.append(listener_thread)

        # If peer IP provided, also attempt outgoing connection
        if peer_ip:
            connector_thread = threading.Thread(
                target=self._connect_out,
                args=(peer_ip,),
                daemon=True
            )
            connector_thread.start()
            threads.append(connector_thread)
            print(f"Connecting to {peer_ip}:{self.connect_port} ...")
        else:
            print(f"Waiting for peer on port {self.listen_port} ...")

        # Wait until one of them succeeds
        connected = self._connected.wait(timeout=CONNECT_TIMEOUT)
        if not connected:
            raise ConnectionError(
                f"No connection established within {CONNECT_TIMEOUT} seconds."
            )

        return self.sock, self.is_initiator

    def _listen(self):
        """Listen for an incoming connection."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(CONNECT_TIMEOUT)

        try:
            server.bind(("0.0.0.0", self.listen_port))
            server.listen(1)
            conn, addr = server.accept()
            conn.settimeout(None)
            with self._lock:
                if not self._connected.is_set():
                    self.is_initiator = False  # This is the responder
                    self.sock = conn
                    self._connected.set()
            print(f"Peer connected from {addr[0]}:{addr[1]}")
        except socket.timeout:
            pass   # connector thread may have already succeeded
        except OSError:
            pass   # port already in use or connection already established
        finally:
            server.close()

    def _connect_out(self, peer_ip: str):
        """Attempt outgoing connection to peer."""
        attempts = 0
        while not self._connected.is_set() and attempts < 10:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((peer_ip, self.connect_port))
                sock.settimeout(None)
                with self._lock:
                    if not self._connected.is_set():
                        self.is_initiator = True  # This is the initiator
                        self.sock = sock
                        self._connected.set()
                print(f"Connected to {peer_ip}:{self.connect_port}")
                return
            except (ConnectionRefusedError, socket.timeout):
                attempts += 1
                time.sleep(2)  # wait before retrying
            except OSError:
                break

    def _set_connection(self, sock: socket.socket):
        """Thread-safe: set the connection if not already established."""
        with self._lock:
            if not self._connected.is_set():
                self.sock = sock
                self._connected.set()
            else:
                sock.close()  # already connected via other thread, discard this one


def get_ports(debug_mode: Optional[str] = None) -> tuple:
    """
    Return (listen_port, connect_port) based on mode.

    Args:
        debug_mode: None, "local", or "remote"

    Returns:
        (listen_port, connect_port)
    """
    if debug_mode == "local":
        return DEBUG_LOCAL_PORT, DEBUG_REMOTE_PORT
    elif debug_mode == "remote":
        return DEBUG_REMOTE_PORT, DEBUG_LOCAL_PORT
    else:
        return DEFAULT_PORT, DEFAULT_PORT


def establish_connection(peer_ip: Optional[str], debug_mode: Optional[str] = None) -> tuple[socket.socket, bool]:
    """
    High-level function to establish a P2P connection.

    Args:
        peer_ip:    IP of the peer to connect to. None = wait for incoming.
        debug_mode: None, "local", or "remote"

    Returns:
        Connected socket ready for send/receive.
    """
    listen_port, connect_port = get_ports(debug_mode)
    peer = PeerConnection(listen_port, connect_port)
    return peer.connect(peer_ip)


# ── Quick self-test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    sys.path.insert(0, "..")

    print("=== P2P Connection Test (debug-local + debug-remote) ===\n")

    results = {}

    def run_local():
        try:
            sock = establish_connection(
                peer_ip="127.0.0.1",
                debug_mode="local"
            )
            results["local"] = sock
        except Exception as e:
            results["local_error"] = str(e)

    def run_remote():
        try:
            sock = establish_connection(
                peer_ip=None,       # just listen
                debug_mode="remote"
            )
            results["remote"] = sock
        except Exception as e:
            results["remote_error"] = str(e)

    t1 = threading.Thread(target=run_remote)
    t2 = threading.Thread(target=run_local)

    t1.start()
    time.sleep(0.2)   # give remote a moment to start listening
    t2.start()

    t1.join(timeout=15)
    t2.join(timeout=15)

    assert "local"  in results, f"Local failed: {results.get('local_error')}"
    assert "remote" in results, f"Remote failed: {results.get('remote_error')}"
    print("Both peers connected successfully ✓")

    # Send a test message through the real protocol
    from protocols.protocol import send_message, receive_message, make_bye

    send_message(results["local"], make_bye())
    msg = receive_message(results["remote"])
    assert msg["type"] == "BYE"
    print("Message sent and received through connection ✓")

    results["local"].close()
    results["remote"].close()
    print("\nAll checks passed.")