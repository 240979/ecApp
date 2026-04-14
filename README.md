# ecApp

A Python-based communication application with Elliptic curve cryptographic features.

## Getting Started

### Prerequisites
Ensure you have Python installed and a **virtual environment** set up in the root directory (`ecApp/venv`).

## Setup & Installation

Since the virtual environment (`venv`) is ignored by Git, you need to set it up locally after cloning the repository.

### 1. Create a Virtual Environment
Open your terminal in the root directory of the project (`ecApp`) and run the following command to create a new virtual environment:

```bash
    python -m venv venv
```
To automatically encrypt logs, you need to add ```.env ``` file into root of the project. If not set, default one will be created.
In the ```.env ``` put ```LOG_SEC_KEY=<your log key> ```. It is not secure, but otherwise you will need to put in the log password every time the app launches. 
This password is used only for logs, so not much can happen, if it is compromised. 
If you run the app with default log password and then change it, you need to delete all contents of ```/logs ```.

### 2. Activate the Virtual Environment
You must activate the environment before running the app or installing packages.

Windows/CLI
```bash
    .\venv\Scripts\Activate.ps1
```

Linux
``` bash
    source venv/bin/activate
```

### 3. Install Dependencies

``` bash
    pip install -r requirements.txt
```
### 4. Launch

``` bash
    python main_app.py
```
For debugging reasons, you can launch two apps on one machine.
To do this, you run the first as
``` bash
    python main_app.py --debug-local
```
and the second with 
``` bash
    python main_app.py --debug-remote
```
This ensures that the apps will not fight over TCP port 25519, which is default.
You can then use "localhost" as target IP address.

### 5. Benchmark and Tests
This project includes an interactive testing suite (`tester.py`) to evaluate the performance and security of the cryptographic implementations. The tool provides three main functionalities:

* **Performance Benchmarks:** Measures execution times for key generation, signing, verifying, and encrypting/decrypting across ECDSA, EdDSA, and ECIES algorithms.
* **Security Validations:** Simulates in-memory attacks (e.g., bit-flipping, signature tampering, and identity spoofing) to ensure the integrity checks and AEAD backends correctly reject invalid or tampered data.
* **Network Simulation:** Runs a local client-server loopback test, ideal for Wireshark inspection, to visibly demonstrate the difference between plaintext communication and ECIES-encrypted traffic over the wire.

To launch the interactive testing interface, run the following command within your virtual environment:
``` bash
    python -m tester.tester
```
Or to enable **graphical visualization** of results run:

``` bash
    python -m tester.tester --plot
```


### 6. Exit the Virtual Environment
``` bash
    deactivate
```
