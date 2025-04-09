#!/usr/bin/env python3
"""
Configuration file for the crypto service.
Contains shared constants used by both the installer and server.
"""

# Service configuration
CRYPTO_SERVICE_NAME = "crypto-server"
CRYPTO_USER = "crypto-service"
CRYPTO_GROUP = "crypto-service"

# File paths
INSTALL_DIR = "/opt/cryptoapp"
KEY_DIR = "/etc/cryptoapp/keys"
KEY_FILE_PATH = "/etc/cryptoapp/keys/encryption.key"
SOCKET_PATH = "/tmp/crypto_server.sock"

# File permissions
KEY_FILE_PERMS = 0o400  # Only owner can read
SOCKET_PERMS = 0o660    # Owner and group can read/write
INSTALL_DIR_PERMS = 0o755  # Owner can read/write/execute, others can read/execute 