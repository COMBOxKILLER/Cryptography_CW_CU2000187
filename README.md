
# Client and server Cryptographic Application 
#Cryptography_CW_CU2000187

## Overview

This application consists of two parts: a server script and a client script. The server listens for incoming connections and supports different encryption methods (RSA, AES, DES) for secure communication. It also features automatic key rotation for enhanced security. The client script can connect to the server, choose an encryption method, and send encrypted data, which the server then decrypts.

## Requirements

- Python 3.x
- PyCryptodome library

## Installation

Ensure you have Python 3.x installed. Then install the PyCryptodome library using pip:

```bash
pip install pycryptodome
```

## Server Code

The server script (`server.py`) performs the following functions:

- Generates an initial RSA key pair and starts a thread for key rotation every hour.
- Listens for incoming client connections on `localhost` and port `12345`.
- Upon client connection, sends the public RSA key to the client.
- Receives encrypted data from the client and decrypts it using the corresponding encryption method (RSA, AES, DES).
- Saves a log of the encryption type, plaintext, and decrypted data hex value in `server_metadata.txt`.

### Usage

Run the server script:

```bash
python server.py
```

## Client Code

The client script (`client.py`) allows the user to:

- Connect to the server at `localhost` on port `12345`.
- Receive the server's public RSA key.
- Choose an encryption method (RSA, AES, DES).
- Send encrypted data to the server using the selected encryption method.

### Usage

Run the client script and follow the interactive prompts:

```bash
python client.py
```

## Notes

- The server and client scripts must be run in different terminal windows or on different machines.
- The client can only connect to the server if the server script is already running.
- Both scripts handle exceptions and close connections gracefully.
