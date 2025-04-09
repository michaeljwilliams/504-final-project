#!/usr/bin/env python3
import os
import sys
import socket
import json
import logging
import argparse
import signal
import base64
import hashlib
import hmac
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pwd
import grp
from config import (
    CRYPTO_USER,
    CRYPTO_GROUP,
    KEY_FILE_PATH,
    SOCKET_PATH,
    SOCKET_PERMS
)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('crypto_server')

class CryptoServer:
    def __init__(self, key_path, socket_path):
        self.key_path = key_path
        self.socket_path = socket_path
        self.running = True
        self.fernet = None
        
        # Load the encryption key
        self._load_key()
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        
    def _load_key(self):
        """Load the encryption key from the key file."""
        try:
            key_file = Path(self.key_path)
            if not key_file.exists():
                logger.error(f"Key file not found at {self.key_path}")
                sys.exit(1)
            
            # Check permissions (should be 0400)
            key_stat = key_file.stat()
            if key_stat.st_mode & 0o077:  # Check if anyone except owner has any permissions
                logger.warning(f"Key file permissions are too open: {oct(key_stat.st_mode)}")
            
            # Load the key
            with open(self.key_path, 'rb') as f:
                key = f.read().strip()
            
            self.fernet = Fernet(key)
            logger.info("Encryption key loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load encryption key: {e}")
            sys.exit(1)
    
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
    
    def encrypt(self, data):
        """Encrypt the given data."""
        if not self.fernet:
            return {'status': 'error', 'message': 'Encryption key not loaded'}
        try:
            if isinstance(data, str):
                data = data.encode()
            encrypted = self.fernet.encrypt(data)
            return {'status': 'success', 'encrypted': base64.b64encode(encrypted).decode()}
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def decrypt(self, data):
        """Decrypt the given data."""
        if not self.fernet:
            return {'status': 'error', 'message': 'Encryption key not loaded'}
        try:
            if isinstance(data, str):
                data = base64.b64decode(data)
            decrypted = self.fernet.decrypt(data)
            return {'status': 'success', 'decrypted': decrypted.decode()}
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def _verify_client(self, connection):
        """Verify the client has permissions to use the service."""
        # For Unix sockets, we can get peer credentials
        try:
            # This would need to be implemented based on the specific requirements
            # Here we could check UID/GID of the connecting process
            # For now, we'll accept all connections
            return True
        except Exception as e:
            logger.error(f"Client verification error: {e}")
            return False
    
    def _process_request(self, data):
        """Process an incoming request."""
        try:
            request = json.loads(data.decode())
            command = request.get('command')
            payload = request.get('payload')
            
            if command == 'encrypt':
                return json.dumps(self.encrypt(payload)).encode()
            elif command == 'decrypt':
                return json.dumps(self.decrypt(payload)).encode()
            else:
                return json.dumps({'status': 'error', 'message': 'Unknown command'}).encode()
        except Exception as e:
            logger.error(f"Error processing request: {e}")
            return json.dumps({'status': 'error', 'message': str(e)}).encode()
    
    def start(self):
        """Start the crypto server."""
        # Make sure socket doesn't already exist
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
        except OSError as e:
            logger.error(f"Error removing existing socket: {e}")
            return
        
        # Create the socket and start listening
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.socket_path)
        
        # Set proper ownership and permissions
        os.chown(self.socket_path, pwd.getpwnam(CRYPTO_USER).pw_uid, grp.getgrnam(CRYPTO_GROUP).gr_gid)
        os.chmod(self.socket_path, 0o660)  # Allow group read/write
        
        sock.listen(1)
        logger.info(f"Server started and listening on {self.socket_path}")
        
        while self.running:
            try:
                # Set a timeout to allow for checking self.running
                sock.settimeout(1.0)
                try:
                    connection, client_address = sock.accept()
                    logger.info("Client connected")
                    
                    # Verify client permissions
                    if not self._verify_client(connection):
                        logger.warning("Client verification failed")
                        connection.close()
                        continue
                    
                    # Process the client request
                    data = connection.recv(4096)
                    if data:
                        response = self._process_request(data)
                        connection.sendall(response)
                    
                    connection.close()
                except socket.timeout:
                    continue
            except Exception as e:
                logger.error(f"Error handling connection: {e}")
        
        # Clean up
        sock.close()
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        logger.info("Server shut down")

def generate_key(key_path):
    """Generate a new encryption key and save it to the specified path."""
    key_dir = os.path.dirname(key_path)
    os.makedirs(key_dir, exist_ok=True)
    
    key = Fernet.generate_key()
    with open(key_path, 'wb') as f:
        f.write(key)
    
    # Set restrictive permissions
    os.chmod(key_path, 0o400)
    logger.info(f"Generated new key and saved to {key_path}")
    return key

def main():
    parser = argparse.ArgumentParser(description='Crypto Server')
    parser.add_argument('--generate-key', action='store_true', help='Generate a new encryption key')
    parser.add_argument('--key-path', default=KEY_FILE_PATH, help='Path to the encryption key file')
    parser.add_argument('--socket-path', default=SOCKET_PATH, help='Path to the Unix socket')
    args = parser.parse_args()
    
    if args.generate_key:
        generate_key(args.key_path)
        return
    
    server = CryptoServer(args.key_path, args.socket_path)
    server.start()

if __name__ == '__main__':
    main() 