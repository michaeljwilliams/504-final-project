# Secure Crypto Service

A Python-based secure cryptography service that keeps secrets protected from users while allowing applications to perform encryption and decryption operations.

## Architecture

This system employs a client-server architecture with privilege separation to ensure that encryption keys are never exposed to regular users:

1. **Crypto Server**: Runs as a privileged service that manages the encryption key and performs cryptographic operations
2. **Client Library**: Provides a simple API for applications to request encryption/decryption services
3. **GUI Application**: Demonstrates how to use the client library with a simple interface

The system uses Unix domain sockets for secure local IPC (Inter-Process Communication) between the client and server components. This approach leverages the Linux permission model to ensure that only authorized processes can communicate with the server.

## Security Features

- Privilege separation between the crypto service and client applications
- Unix domain socket permission controls
- Server runs as a dedicated user with minimal privileges
- Encryption key stored with restrictive file permissions (0400)
- Process credential verification for client authentication

## Installation

### Requirements

- Linux system with systemd (Ubuntu 18.04+ or similar)
- Python 3.6+ with the following packages:
  - cryptography
  - tkinter (for the GUI)

### Steps

1. Clone the repository
2. Install dependencies:
   ```
   pip3 install cryptography
   ```

3. Run the installer as root:
   ```
   sudo python3 install.py
   ```

The installer will:
- Create a dedicated service user and group
- Install the crypto server as a systemd service
- Generate an encryption key with proper permissions
- Set up the client tools

## Usage

### Command Line Interface

```bash
# Encrypt data
crypto-client encrypt "my secret data"

# Decrypt data
crypto-client decrypt "gAAAAABkX..."
```

### GUI Application

```bash
crypto-gui
```

### Integrating with Your Applications

```python
from crypto_client import CryptoClient

# Create a client
client = CryptoClient()

# Encrypt data
result = client.encrypt("secret data")
if result['status'] == 'success':
    encrypted_data = result['encrypted']
    print(f"Encrypted: {encrypted_data}")

# Decrypt data
result = client.decrypt(encrypted_data)
if result['status'] == 'success':
    decrypted_data = result['decrypted']
    print(f"Decrypted: {decrypted_data}")
```

## Uninstallation

```bash
sudo python3 install.py --uninstall
```

## How It Works

1. When an application needs to encrypt or decrypt data, it connects to the crypto server using a Unix domain socket.
2. The server verifies the client's credentials to ensure it has permission to access the service.
3. The client sends a JSON request with the command ('encrypt' or 'decrypt') and the payload.
4. The server performs the cryptographic operation using the secret key that is stored securely.
5. The result is sent back to the client application, which never has access to the encryption key.

## Security Considerations

- This system protects the encryption key from user inspection but cannot protect against all attacks (e.g., memory inspection by root users).
- The Unix socket location (/tmp/crypto_server.sock) is secured with file permissions but might need additional protection in multi-user environments.
- For production use, consider more stringent access controls and socket placement in a restricted directory.

## Virtual Machine Testing

For testing purposes, this application can be installed in a virtual machine running Ubuntu 18.04 or newer. Simply follow the standard installation instructions above after setting up your VM.

It's recommended to use a VM with a graphical environment for testing the GUI application. The VM should have Python 3 installed with the required dependencies. 