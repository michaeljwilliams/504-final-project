#!/usr/bin/env python3
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import queue
import logging

# Import our crypto client
from crypto_client import CryptoClient

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('crypto_gui')

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto Client GUI")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Create the crypto client
        self.client = CryptoClient()
        
        # Create a queue for thread-safe communication
        self.queue = queue.Queue()
        
        # Create UI elements
        self.create_widgets()
        
        # Start checking the queue
        self.check_queue()
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Input Data", padding="10")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=8)
        self.input_text.pack(fill=tk.BOTH, expand=True)
        
        # Buttons section
        button_frame = ttk.Frame(main_frame, padding="5")
        button_frame.pack(fill=tk.X, pady=5)
        
        encrypt_button = ttk.Button(button_frame, text="Encrypt", command=self.encrypt_data)
        encrypt_button.pack(side=tk.LEFT, padx=5)
        
        decrypt_button = ttk.Button(button_frame, text="Decrypt", command=self.decrypt_data)
        decrypt_button.pack(side=tk.LEFT, padx=5)
        
        clear_button = ttk.Button(button_frame, text="Clear", command=self.clear_data)
        clear_button.pack(side=tk.RIGHT, padx=5)
        
        # Output section
        output_frame = ttk.LabelFrame(main_frame, text="Output Data", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=8)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=5)
    
    def encrypt_data(self):
        """Encrypt the data in the input text area."""
        data = self.input_text.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Warning", "No data to encrypt")
            return
        
        self.status_var.set("Encrypting...")
        self.root.update_idletasks()
        
        # Run encryption in a separate thread to avoid blocking the UI
        threading.Thread(target=self._encrypt_thread, args=(data,), daemon=True).start()
    
    def _encrypt_thread(self, data):
        try:
            result = self.client.encrypt(data)
            self.queue.put(("encrypt", result))
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            self.queue.put(("error", str(e)))
    
    def decrypt_data(self):
        """Decrypt the data in the input text area."""
        data = self.input_text.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("Warning", "No data to decrypt")
            return
        
        self.status_var.set("Decrypting...")
        self.root.update_idletasks()
        
        # Run decryption in a separate thread to avoid blocking the UI
        threading.Thread(target=self._decrypt_thread, args=(data,), daemon=True).start()
    
    def _decrypt_thread(self, data):
        try:
            result = self.client.decrypt(data)
            self.queue.put(("decrypt", result))
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            self.queue.put(("error", str(e)))
    
    def clear_data(self):
        """Clear both text areas."""
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.status_var.set("Ready")
    
    def check_queue(self):
        """Check the queue for results from the worker threads."""
        try:
            operation, result = self.queue.get(block=False)
            
            if operation == "error":
                messagebox.showerror("Error", result)
                self.status_var.set("Error")
            elif operation in ["encrypt", "decrypt"]:
                if result['status'] == 'success':
                    if operation == "encrypt":
                        output = result['encrypted']
                        self.status_var.set("Encryption successful")
                    else:  # decrypt
                        output = result['decrypted']
                        self.status_var.set("Decryption successful")
                    
                    self.output_text.delete("1.0", tk.END)
                    self.output_text.insert("1.0", output)
                else:
                    messagebox.showerror("Error", result['message'])
                    self.status_var.set(f"Error: {result['message']}")
            
            self.queue.task_done()
        except queue.Empty:
            pass
        finally:
            # Schedule to check again after 100ms
            self.root.after(100, self.check_queue)

def main():
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 