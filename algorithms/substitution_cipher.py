import random
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

class SubstitutionCipher:
    def __init__(self, key=None):
        if key:
            if self.check_key(key):
                self.key = key
            else:
                print("Invalid key. Generating a random key instead.")
                self.key = self.get_random_key()
        else:
            self.key = self.get_random_key()

    def get_random_key(self):
        random_list = list(LETTERS)
        random.shuffle(random_list)
        return ''.join(random_list)

    def check_key(self, key):
        return sorted(key.upper()) == list(LETTERS)

    def translate_message(self, message, mode):
        translated = ''
        chars_a = LETTERS
        chars_b = self.key
        if mode == 'D':
            chars_a, chars_b = chars_b, chars_a
        for symbol in message:
            if symbol.upper() in chars_a:
                sym_index = chars_a.find(symbol.upper())
                if symbol.isupper():
                    translated += chars_b[sym_index].upper()
                else:
                    translated += chars_b[sym_index].lower() 
            else:
                translated += symbol
        return translated

class SubstitutionCipherUI:
    def __init__(self, master):
        self.master = master
        self.master.winfo_toplevel().title("Substitution Cipher")
        
        # Header
        self.header_label = ttk.Label(master, text="Substitution Cipher", font=("Helvetica", 20, "bold"))
        self.header_label.grid(row=0, column=0, columnspan=3, pady=10)

        # Divider
        self.divider = ttk.Separator(master, orient="horizontal")
        self.divider.grid(row=1, column=0, columnspan=3, sticky="ew", pady=10)

        # Encryption Header
        self.encryption_header_label = ttk.Label(master, text="Encryption", font=("Helvetica", 16, "bold"))
        self.encryption_header_label.grid(row=2, column=0, sticky="w", padx=10)

        # Decryption Header
        self.decryption_header_label = ttk.Label(master, text="Decryption", font=("Helvetica", 16, "bold"))
        self.decryption_header_label.grid(row=2, column=1, sticky="w", padx=10)

        # File Chooser Buttons
        self.encryption_file_button = ttk.Button(master, text="Choose File", command=self.encrypt_from_file)
        self.encryption_file_button.grid(row=3, column=0, padx=10, pady=5)

        self.decryption_file_button = ttk.Button(master, text="Choose File", command=self.decrypt_from_file)
        self.decryption_file_button.grid(row=3, column=1, padx=10, pady=5)

        # Encryption Text Entry
        self.encryption_text_label = ttk.Label(master, text="Plaintext:")
        self.encryption_text_label.grid(row=4, column=0, sticky="w", padx=10)
        self.encryption_text_entry = ttk.Entry(master)
        self.encryption_text_entry.grid(row=5, column=0, padx=(10, 5), sticky="ew")

        # Decryption Text Entry
        self.decryption_text_label = ttk.Label(master, text="Ciphertext:")
        self.decryption_text_label.grid(row=4, column=1, sticky="w", padx=10)
        self.decryption_text_entry = ttk.Entry(master)
        self.decryption_text_entry.grid(row=5, column=1, padx=(5, 10), sticky="ew")

        # Key Entry
        self.key_label = ttk.Label(master, text="Key:")
        self.key_label.grid(row=6, column=0, sticky="w", padx=10)
        self.key_value = tk.StringVar()
        self.key_entry = ttk.Entry(master, textvariable=self.key_value)
        self.key_entry.grid(row=7, column=0, padx=10, sticky="ew")

        # Encryption Button
        self.encrypt_button = ttk.Button(master, text="Encrypt", command=self.encrypt_text,width=10,style='Rounded.TButton')
        self.encrypt_button.grid(row=8, column=0, pady=10, padx=(10, 5), sticky="ew")

        # Decryption Button
        self.decrypt_button = ttk.Button(master, text="Decrypt", command=self.decrypt_text,width=10,style='Rounded.TButton')
        self.decrypt_button.grid(row=8, column=1, pady=10, padx=(5, 10), sticky="ew")

        # Output
        self.output_label = ttk.Label(master, text="Result:", font=("Helvetica", 16, "bold"))
        self.output_label.grid(row=9, column=0, columnspan=2, pady=10)

        self.output_text = tk.Text(master, height=10, width=50,state=tk.DISABLED)
        self.output_text.grid(row=10, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        # Create a scrollbar
        self.scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.output_text.yview)
        self.scrollbar.grid(row=10, column=2, sticky="ns")
        
        # Attach the scrollbar to the Text widget
        self.output_text.config(yscrollcommand=self.scrollbar.set)

        # Save Result Button
        self.save_button = ttk.Button(master, text="Save Result", command=self.save_result)
        self.save_button.grid(row=11, column=0, columnspan=2, pady=10, padx=10)

        # Configure grid row and column weights to take remaining space
        master.grid_columnconfigure((1, 0), weight=1)

        # Create a custom style for rounded buttons
        style = ttk.Style()
        style.configure('Rounded.TButton', borderwidth=0, relief="flat", foreground="black", background="#4CAF50")
        style.map('Rounded.TButton', background=[('active', '#45a049')])

        # Initialize SubstitutionCipher
        self.cipher = None

    def encrypt_text(self):
        text = self.encryption_text_entry.get()
        key = self.key_value.get()
        if not key or not self.cipher or not self.cipher.check_key(key):
            self.cipher = SubstitutionCipher(key)
            self.key_value.set(self.cipher.key)
        else:
            self.cipher.key = key  # Update the key
        encrypted = self.cipher.translate_message(text, mode='E')
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert(tk.END, encrypted)
        self.output_text.config(state=tk.DISABLED)

    def decrypt_text(self):
        text = self.decryption_text_entry.get()
        key = self.key_value.get()
        if not key or not self.cipher or not self.cipher.check_key(key):
            self.cipher = SubstitutionCipher(key)
            self.key_value.set(self.cipher.key)
        else:
            self.cipher.key = key  # Update the key
        decrypted = self.cipher.translate_message(text, mode='D')
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert(tk.END, decrypted)
        self.output_text.config(state=tk.DISABLED)

    def encrypt_from_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                text = file.read()
            self.encryption_text_entry.delete(0, tk.END)
            self.encryption_text_entry.insert(tk.END, text)
            self.encrypt_text()

    def decrypt_from_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                text = file.read()
            self.decryption_text_entry.delete(0, tk.END)
            self.decryption_text_entry.insert(tk.END, text)
            self.decrypt_text()

    def save_result(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.output_text.get('1.0', tk.END))

def main():
    root = tk.Tk()
    app = SubstitutionCipherUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
