# ecApp

A Python-based communication application with Elliptic curve cryptographic features.

## Getting Started

### Prerequisites
Ensure you have Python installed and a **virtual environment** set up in the root directory (`ecApp/venv`).

### Running the Application
To start the main application, navigate to the project root folder (`ecApp`) and run the following command within your activated virtual environment:

```bash
python -m app.app
```

## Setup & Installation

Since the virtual environment (`venv`) is ignored by Git, you need to set it up locally after cloning the repository.

### 1. Create a Virtual Environment
Open your terminal in the root directory of the project (`ecApp`) and run the following command to create a new virtual environment:

```bash
    python -m venv venv
```

### 2. Activate the Virtual Environment
You must activate the environment before running the app or installing packages.

Windows/CLI
```bash
    .\venv\Scripts\activate.ps1
```

Linux
``` bash
    source venv/bin/activate
```

### 3. Install Dependencies

``` bash
    pip install -r requirements.txt
```

### 4. Exit the Virtual Environment
``` bash
    deactivate
```
