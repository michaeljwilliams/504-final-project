#!/usr/bin/env python3
import os
import socket
import json
import base64
import logging
from typing import Dict, Any, Union

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('crypto_client')

# Default socket path
DEFAULT_SOCKET_PATH = '/tmp/crypto_server.sock'

class CryptoClient:
    """Client for interacting with the crypto server."""
    
    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH):
        """Initialize the crypto client.
        
        Args:
            socket_path: Path to the Unix domain socket for the crypto server
        """
        self.socket_path = socket_path
    
    def _send_request(self, command: str, payload: Any) -> Dict[str, Any]:
        """Send a request to the crypto server and return the response.
        
        Args:
            command: The command to execute ('encrypt' or 'decrypt')
            payload: The data to encrypt or decrypt
            
        Returns:
            A dictionary containing the server response
        """
        if not os.path.exists(self.socket_path):
            logger.error(f"Socket {self.socket_path} does not exist. Is the crypto server running?")
            return {'status': 'error', 'message': f"Socket {self.socket_path} does not exist"}
        
        # Create the socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        
        try:
            # Connect to the server
            sock.connect(self.socket_path)
            
            # Prepare and send the request
            request = {
                'command': command,
                'payload': payload
            }
            sock.sendall(json.dumps(request).encode())
            
            # Get the response
            response = sock.recv(4096)
            return json.loads(response.decode())
        except Exception as e:
            logger.error(f"Error communicating with crypto server: {e}")
            return {'status': 'error', 'message': str(e)}
        finally:
            sock.close()
    
    def encrypt(self, data: Union[str, bytes]) -> Dict[str, Any]:
        """Encrypt data.
        
        Args:
            data: The data to encrypt. Can be a string or bytes.
            
        Returns:
            A dictionary containing the encrypted data or an error message.
        """
        # Ensure data is a string for JSON serialization
        if isinstance(data, bytes):
            data = base64.b64encode(data).decode()
        
        return self._send_request('encrypt', data)
    
    def decrypt(self, encrypted_data: Union[str, bytes]) -> Dict[str, Any]:
        """Decrypt data.
        
        Args:
            encrypted_data: The data to decrypt. Can be a base64 string or bytes.
            
        Returns:
            A dictionary containing the decrypted data or an error message.
        """
        # Ensure data is a string for JSON serialization
        if isinstance(encrypted_data, bytes):
            encrypted_data = base64.b64encode(encrypted_data).decode()
        
        return self._send_request('decrypt', encrypted_data)

# Simple example of usage
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} [encrypt|decrypt] <data>")
        sys.exit(1)
    
    client = CryptoClient()
    command = sys.argv[1].lower()
    data = sys.argv[2]
    
    if command == 'encrypt':
        result = client.encrypt(data)
        if result['status'] == 'success':
            print(f"Encrypted: {result['encrypted']}")
        else:
            print(f"Error: {result['message']}")
    elif command == 'decrypt':
        result = client.decrypt(data)
        if result['status'] == 'success':
            print(f"Decrypted: {result['decrypted']}")
        else:
            print(f"Error: {result['message']}")
    else:
        print(f"Unknown command: {command}")
        sys.exit(1) 