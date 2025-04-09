# Secure Crypto Service

A Python-based secure cryptography service that keeps secrets protected from users while allowing applications to perform encryption and decryption operations.

## Architecture

This system employs a client-server architecture with privilege separation to ensure that encryption keys are never exposed to regular users:

1. **Crypto Server**: Runs as a privileged service that manages the encryption key and performs cryptographic operations
2. **Client Library**: Provides a simple API for applications to request encryption/decryption services
3. **GUI Application**: Uses the client library with a simple interface

## Security Features

- Privilege separation between the crypto service and client applications
- Unix domain socket permission controls - only authorized processes can communicate with the server
- Server runs as a dedicated user with minimal privileges
- Encryption key stored with restrictive file permissions (0400)
- Process credential verification for client authentication - only users in the dedicated group can access the service

## Installation

### Requirements

- Linux system with systemd (Ubuntu 18.04+ or similar)
- Python 3.6+ with the following packages:
  - cryptography (for cryptographic operations)
  - tkinter (for the GUI application)
  - systemd (for service management)

### Steps

1. Clone the repository
2. Install dependencies:
   ```bash
   # On Ubuntu/Debian, install required packages
   sudo apt-get update
   sudo apt install python3
   sudo apt install python3-cryptography
   sudo apt install python3-tk
   ```

*Optional: Change the default configuration values in config.py.*

3. Run the installer as root:
   ```
   sudo python3 install.py
   ```

The installer will:
- Create a dedicated service user and group
- Install the crypto server as a systemd service
- Generate an encryption key with proper permissions
- Set up the client tools

4. Add users to the crypto-service group:
   ```bash
   # Add a user to the crypto-service group
   sudo usermod -a -G crypto-service username
   
   # IMPORTANT: Users must log out and log back in for group changes to take effect
   # The new group membership will not be active until the next login
   ```

## Usage

### Command Line Interface

```bash
# Encrypt data
crypto-client encrypt "my secret data"

# Decrypt data
crypto-client decrypt "gAAAAABkX..."
```

### GUI Application
Start from a terminal:
```bash
crypto-gui &
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

# Potential improvements for production use
- More stringent access controls and socket placement in a restricted directory
- Use TLS for server-client communication instead of sockets
- Authenticate users with PKI instead of local credentials
- Separate client and server by putting the server on another machine - prevents possible memory inspection from clients that are able to elevate privileges
- Keep access logs
- Add ability to use multiple secrets
- Use a stronger cryptographic algorithm/library than Fernet (AES-128 CBC)
- Make the app more portable by adding Windows support via OS detection, service account (Windows Server only), and DPAPI; or employ a networked model with server on a separate machine for maximum portability
