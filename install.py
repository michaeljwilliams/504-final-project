#!/usr/bin/env python3
import os
import sys
import shutil
import argparse
import subprocess
import logging
import pwd
import grp
from config import (
    CRYPTO_SERVICE_NAME,
    CRYPTO_USER,
    CRYPTO_GROUP,
    INSTALL_DIR,
    KEY_DIR,
    KEY_FILE_PATH,
    SOCKET_PATH,
    KEY_FILE_PERMS,
    INSTALL_DIR_PERMS
)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('crypto_installer')

# Systemd service file template
SYSTEMD_SERVICE_TEMPLATE = """[Unit]
Description=Crypto Server Service
After=network.target

[Service]
Type=simple
User={user}
Group={group}
ExecStart={exec_path} --key-path={key_path} --socket-path={socket_path}
Restart=on-failure
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=crypto-server

[Install]
WantedBy=multi-user.target
"""

def check_root():
    """Check if the script is run as root."""
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        sys.exit(1)

def create_user_and_group():
    """Create a dedicated user and group for the crypto service."""
    try:
        # Check if group exists
        try:
            grp.getgrnam(CRYPTO_GROUP)
            logger.info(f"Group {CRYPTO_GROUP} already exists")
        except KeyError:
            subprocess.check_call(["groupadd", CRYPTO_GROUP])
            logger.info(f"Created group {CRYPTO_GROUP}")
        
        # Check if user exists
        try:
            pwd.getpwnam(CRYPTO_USER)
            logger.info(f"User {CRYPTO_USER} already exists")
        except KeyError:
            subprocess.check_call([
                "useradd",
                "-r",  # System account
                "-g", CRYPTO_GROUP,  # Assign to the crypto group
                "-s", "/usr/sbin/nologin",  # No login shell
                "-d", "/nonexistent",  # No home directory
                "-c", "Crypto Service",  # Comment
                CRYPTO_USER
            ])
            logger.info(f"Created user {CRYPTO_USER}")
        
        return True
    except Exception as e:
        logger.error(f"Failed to create user and group: {e}")
        return False

def install_files():
    """Install the crypto server files to the installation directory."""
    try:
        # Create installation directory
        os.makedirs(INSTALL_DIR, exist_ok=True)
        
        # Copy the server script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        server_script = os.path.join(script_dir, "crypto_server.py")
        client_script = os.path.join(script_dir, "crypto_client.py")
        gui_script = os.path.join(script_dir, "crypto_gui.py")
        config_script = os.path.join(script_dir, "config.py")
        
        shutil.copy2(server_script, os.path.join(INSTALL_DIR, "crypto_server.py"))
        shutil.copy2(client_script, os.path.join(INSTALL_DIR, "crypto_client.py"))
        shutil.copy2(gui_script, os.path.join(INSTALL_DIR, "crypto_gui.py"))
        shutil.copy2(config_script, os.path.join(INSTALL_DIR, "config.py"))
        
        # Make the server script executable
        server_path = os.path.join(INSTALL_DIR, "crypto_server.py")
        os.chmod(server_path, 0o755)
        
        # Create the key directory
        os.makedirs(KEY_DIR, exist_ok=True)
        
        # Set proper permissions
        os.chown(INSTALL_DIR, 0, 0)  # root:root for install dir
        os.chmod(INSTALL_DIR, INSTALL_DIR_PERMS)
        
        os.chown(KEY_DIR, pwd.getpwnam(CRYPTO_USER).pw_uid, grp.getgrnam(CRYPTO_GROUP).gr_gid)
        os.chmod(KEY_DIR, 0o700)  # Only the crypto user can access it
        
        logger.info("Files installed successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to install files: {e}")
        return False

def generate_key():
    """Generate a new encryption key."""
    try:
        # Use the server to generate the key
        server_path = os.path.join(INSTALL_DIR, "crypto_server.py")
        subprocess.check_call([server_path, "--generate-key", "--key-path", KEY_FILE_PATH])
        
        # Set proper permissions on the key file
        os.chown(KEY_FILE_PATH, pwd.getpwnam(CRYPTO_USER).pw_uid, grp.getgrnam(CRYPTO_GROUP).gr_gid)
        os.chmod(KEY_FILE_PATH, KEY_FILE_PERMS)
        
        logger.info(f"Encryption key generated at {KEY_FILE_PATH}")
        return True
    except Exception as e:
        logger.error(f"Failed to generate key: {e}")
        return False

def install_systemd_service():
    """Install the systemd service."""
    try:
        service_file = f"/etc/systemd/system/{CRYPTO_SERVICE_NAME}.service"
        
        # Create the service file
        with open(service_file, 'w') as f:
            service_content = SYSTEMD_SERVICE_TEMPLATE.format(
                user=CRYPTO_USER,
                group=CRYPTO_GROUP,
                exec_path=os.path.join(INSTALL_DIR, "crypto_server.py"),
                key_path=os.path.join(KEY_DIR, "encryption.key"),
                socket_path=SOCKET_PATH
            )
            f.write(service_content)
        
        # Set proper permissions
        os.chmod(service_file, 0o644)
        
        # Create socket directory if it doesn't exist
        socket_dir = os.path.dirname(SOCKET_PATH)
        os.makedirs(socket_dir, exist_ok=True)
        
        # Reload systemd, enable and start the service
        subprocess.check_call(["systemctl", "daemon-reload"])
        subprocess.check_call(["systemctl", "enable", CRYPTO_SERVICE_NAME])
        subprocess.check_call(["systemctl", "start", CRYPTO_SERVICE_NAME])
        
        logger.info(f"Systemd service {CRYPTO_SERVICE_NAME} installed and started")
        return True
    except Exception as e:
        logger.error(f"Failed to install systemd service: {e}")
        return False

def create_client_symlink():
    """Create a symlink for the client script in /usr/local/bin."""
    try:
        client_path = os.path.join(INSTALL_DIR, "crypto_client.py")
        gui_path = os.path.join(INSTALL_DIR, "crypto_gui.py")
        
        # Create symlinks
        if os.path.exists("/usr/local/bin/crypto-client"):
            os.unlink("/usr/local/bin/crypto-client")
        
        if os.path.exists("/usr/local/bin/crypto-gui"):
            os.unlink("/usr/local/bin/crypto-gui")
        
        os.symlink(client_path, "/usr/local/bin/crypto-client")
        os.symlink(gui_path, "/usr/local/bin/crypto-gui")
        
        # Make them executable
        os.chmod(client_path, 0o755)
        os.chmod(gui_path, 0o755)
        
        logger.info("Client symlinks created in /usr/local/bin")
        return True
    except Exception as e:
        logger.error(f"Failed to create client symlinks: {e}")
        return False

def uninstall():
    """Uninstall the crypto service."""
    try:
        # Stop and disable the service
        try:
            subprocess.check_call(["systemctl", "stop", CRYPTO_SERVICE_NAME])
            subprocess.check_call(["systemctl", "disable", CRYPTO_SERVICE_NAME])
        except subprocess.CalledProcessError:
            logger.warning("Failed to stop/disable service (might not be installed)")
        
        # Remove service file
        service_file = f"/etc/systemd/system/{CRYPTO_SERVICE_NAME}.service"
        if os.path.exists(service_file):
            os.unlink(service_file)
            subprocess.check_call(["systemctl", "daemon-reload"])
        
        # Remove symlinks
        if os.path.exists("/usr/local/bin/crypto-client"):
            os.unlink("/usr/local/bin/crypto-client")
        
        if os.path.exists("/usr/local/bin/crypto-gui"):
            os.unlink("/usr/local/bin/crypto-gui")
        
        # Ask about removing files and user
        if input("Remove installation directory and keys? (y/n): ").lower() == 'y':
            shutil.rmtree(INSTALL_DIR, ignore_errors=True)
            shutil.rmtree(KEY_DIR, ignore_errors=True)
        
        if input("Remove crypto service user and group? (y/n): ").lower() == 'y':
            try:
                subprocess.check_call(["userdel", CRYPTO_USER])
                subprocess.check_call(["groupdel", CRYPTO_GROUP])
            except subprocess.CalledProcessError:
                logger.warning("Failed to remove user/group (might not exist)")
        
        logger.info("Uninstallation complete")
        return True
    except Exception as e:
        logger.error(f"Failed to uninstall: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Crypto Service Installer")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall the crypto service")
    
    args = parser.parse_args()
    
    # Check if running as root
    check_root()
    
    if args.uninstall:
        uninstall()
        return
    
    # Install steps
    logger.info("Installing crypto service...")
    
    steps = [
        ("Creating user and group", create_user_and_group),
        ("Installing files", install_files),
        ("Generating encryption key", generate_key),
        ("Installing systemd service", install_systemd_service),
        ("Creating client symlinks", create_client_symlink)
    ]
    
    for description, step_func in steps:
        logger.info(description)
        if not step_func():
            logger.error(f"Installation failed at step: {description}")
            return
    
    logger.info("Installation completed successfully")
    logger.info("The crypto service is now running. You can use 'crypto-client' and 'crypto-gui' to interact with it.")
    logger.info(f"Service status: systemctl status {CRYPTO_SERVICE_NAME}")

if __name__ == "__main__":
    main() 