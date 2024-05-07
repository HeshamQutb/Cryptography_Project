import tkinter as tk
from tkinter import ttk
from tkinter.font import Font
from PIL import Image, ImageTk
from collections import Counter
from tkinter import filedialog

class CaesarCipher:
    def __init__(self, shift):
        self.shift = shift % 26

    def encrypt(self, text):
        encrypted_text = ""
        for char in text:
            if char.isupper():
                encrypted_text += chr((ord(char) + self.shift - 65) % 26 + 65)
            elif char.islower():
                encrypted_text += chr((ord(char) + self.shift - 97) % 26 + 97)
            else:
                encrypted_text += char
        return encrypted_text

    def decrypt(self, ciphertext):
        decrypted_text = ""
        for char in ciphertext:
            if char.isupper():
                decrypted_text += chr((ord(char) - self.shift - 65) % 26 + 65)
            elif char.islower():
                decrypted_text += chr((ord(char) - self.shift - 97) % 26 + 97)
            else:
                decrypted_text += char
        return decrypted_text

    def brute_force_decrypt(self, ciphertext):
        LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        letters = 'abcdefghijklmnopqrstuvwxyz'
        decrypted_results = []
        for key in range(len(LETTERS)):
            translated = ""
            for symbol in ciphertext:
                if symbol in LETTERS:
                    num = LETTERS.find(symbol)
                    new_index = (num - key) % len(LETTERS)
                    translated += LETTERS[new_index]
                elif symbol in letters:
                    num = letters.find(symbol)
                    new_index = (num - key) % len(letters)
                    translated += letters[new_index]
                else:
                    translated += symbol
            decrypted_results.append(translated)
        return decrypted_results


class CaesarCipherUI:
    def __init__(self, master):
        self.master = master
        self.master.winfo_toplevel().title("Caesar Cipher")

        # Add empty columns for left padding
        self.empty_left_col_1 = ttk.Label(master, text="")
        self.empty_left_col_1.grid(row=0, column=0, padx=20)
        self.empty_left_col_2 = ttk.Label(master, text="")
        self.empty_left_col_2.grid(row=1, column=0, padx=20)

        # Header
        self.header_label = ttk.Label(master, text="Caesar Cipher", font=("Helvetica", 20, "bold"))
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

        # Key Selection
        self.key_label = ttk.Label(master, text="Key:")
        self.key_label.grid(row=6, column=0, sticky="w", padx=10)
        self.key_value = tk.IntVar()
        self.key_spinbox = ttk.Spinbox(master, from_=0, to=25, textvariable=self.key_value, width=5)
        self.key_spinbox.grid(row=7, column=0, padx=10, sticky="ew")

        # Encryption Button
        self.encrypt_button = ttk.Button(master, text="Encrypt", command=self.encrypt_text, width=10, style='Rounded.TButton')
        self.encrypt_button.grid(row=8, column=0, pady=10, padx=(10, 5), sticky="ew")

        # Decryption Button
        self.decrypt_button = ttk.Button(master, text="Decrypt", command=self.decrypt_text, width=10, style='Rounded.TButton')
        self.decrypt_button.grid(row=8, column=1, pady=10, padx=(5, 10), sticky="ew")

        # Brute Force Decryption Button
        self.brute_force_decrypt_button = ttk.Button(master, text="Brute Force", command=self.brute_force_decrypt_text, width=15, style='Rounded.TButton')
        self.brute_force_decrypt_button.grid(row=9, column=0, columnspan=2, pady=10, padx=10)

        # Output
        self.output_label = ttk.Label(master, text="Result:", font=("Helvetica", 16, "bold"))
        self.output_label.grid(row=10, column=0, columnspan=2, pady=10)

        self.output_text = tk.Text(master, height=10, width=50, state=tk.DISABLED)
        self.output_text.grid(row=11, column=0, columnspan=2, sticky="ew", padx=10)

        # Create a scrollbar
        self.scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.output_text.yview)
        self.scrollbar.grid(row=11, column=2, sticky="ns")

        # Attach the scrollbar to the Text widget
        self.output_text.config(yscrollcommand=self.scrollbar.set)

        # Save Result Button
        self.save_button = ttk.Button(master, text="Save Result", command=self.save_result)
        self.save_button.grid(row=12, column=0, columnspan=2, pady=10, padx=10)

        # Configure grid row and column weights to take remaining space
        master.grid_columnconfigure((1, 0), weight=1)

        # Create a custom style for rounded buttons
        style = ttk.Style()
        style.configure('Rounded.TButton', borderwidth=0, relief="flat", foreground="black", background="#4CAF50")
        style.map('Rounded.TButton', background=[('active', '#45a049')])

    def encrypt_text(self):
        text = self.encryption_text_entry.get()
        key = self.key_value.get()
        cipher = CaesarCipher(key)
        encrypted = cipher.encrypt(text)
        self.output_text.config(state=tk.NORMAL)  # Set state to NORMAL to allow editing
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert(tk.END, encrypted)
        self.output_text.config(state=tk.DISABLED)  # Set state back to DISABLED to make it read-only

    def decrypt_text(self):
        text = self.decryption_text_entry.get()
        key = self.key_value.get()
        cipher = CaesarCipher(key)
        decrypted = cipher.decrypt(text)
        self.output_text.config(state=tk.NORMAL)  # Set state to NORMAL to allow editing
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert(tk.END, decrypted)
        self.output_text.config(state=tk.DISABLED)  # Set state back to DISABLED to make it read-only

    def brute_force_decrypt_text(self):
        text = self.decryption_text_entry.get()
        cipher = CaesarCipher(0)  # Shift value is not required for brute-force decryption
        decrypted_results = cipher.brute_force_decrypt(text)
        self.output_text.config(state=tk.NORMAL)  # Set state to NORMAL to allow editing
        self.output_text.delete('1.0', tk.END)
        for key, decrypted in enumerate(decrypted_results):
            self.output_text.insert(tk.END, f"Hacking key #{key}: {decrypted}\n")
        self.output_text.config(state=tk.DISABLED)  # Set state back to DISABLED to make it read-only

    def encrypt_from_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                text = file.read()
            self.encryption_text_entry.delete(0, tk.END)
            self.encryption_text_entry.insert(tk.END, text)

            # Automatically encrypt the text after reading from file
            self.encrypt_text()

    def decrypt_from_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                text = file.read()
            self.decryption_text_entry.delete(0, tk.END)
            self.decryption_text_entry.insert(tk.END, text)

            # Automatically decrypt the text after reading from file
            self.decrypt_text()

    def save_result(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.output_text.get('1.0', tk.END))

def main():
    root = tk.Tk()
    app = CaesarCipherUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
