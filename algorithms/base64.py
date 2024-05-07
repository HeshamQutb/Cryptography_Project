import base64
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog

class Base64Cipher:
    @staticmethod
    def encode(message):
        message_bytes = message.encode('utf-8')
        base64_bytes = base64.b64encode(message_bytes)
        return base64_bytes.decode('utf-8')
    
    @staticmethod
    def decode(base64_message):
        base64_bytes = base64_message.encode('utf-8')
        message_bytes = base64.b64decode(base64_bytes)
        return message_bytes.decode('utf-8')

class Base64CipherUI:
    def __init__(self, master):
        self.master = master
        self.master.winfo_toplevel().title("Base64 Cipher")

        # Header
        self.header_label = ttk.Label(master, text="Base64 Cipher", font=("Helvetica", 20, "bold"))
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
        self.encryption_file_button = ttk.Button(master, text="Choose File to Encode", command=self.encode_from_file)
        self.encryption_file_button.grid(row=3, column=0, padx=10, pady=5)

        self.decryption_file_button = ttk.Button(master, text="Choose File to Decode", command=self.decode_from_file)
        self.decryption_file_button.grid(row=3, column=1, padx=10, pady=5)

        # Encryption Text Entry
        self.encryption_text_entry = ttk.Entry(master, width=50)
        self.encryption_text_entry.grid(row=4, column=0, padx=10, pady=10, sticky="ew")

        # Decryption Text Entry
        self.decryption_text_entry = ttk.Entry(master, width=50)
        self.decryption_text_entry.grid(row=4, column=1, padx=10, pady=10, sticky="ew")

        # Encode and Decode Buttons
        self.encode_button = ttk.Button(master, text="Encode", command=self.encode_text,style='Rounded.TButton')
        self.encode_button.grid(row=5, column=0, padx=10, pady=10)

        self.decode_button = ttk.Button(master, text="Decode", command=self.decode_text,style='Rounded.TButton')
        self.decode_button.grid(row=5, column=1, padx=10, pady=10)
        
        
        
        # Output
        self.output_label = ttk.Label(master, text="Result:", font=("Helvetica", 16, "bold"))
        self.output_label.grid(row=6, column=0, columnspan=2, pady=10)

        self.output_text = tk.Text(master, height=10, width=50, state=tk.DISABLED)
        self.output_text.grid(row=7, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        # Create a scrollbar
        self.scrollbar = ttk.Scrollbar(master, orient="vertical", command=self.output_text.yview)
        self.scrollbar.grid(row=7, column=2, sticky="ns")
        
        # Save Result Button
        self.save_button = ttk.Button(master, text="Save Result", command=self.save_result)
        self.save_button.grid(row=8, column=0, columnspan=2, pady=10)

        # Attach the scrollbar to the Text widget
        self.output_text.config(yscrollcommand=self.scrollbar.set)

        # Configure grid row and column weights to take remaining space
        master.grid_columnconfigure((1, 0), weight=1)

        # Create a custom style for rounded buttons
        style = ttk.Style()
        style.configure('Rounded.TButton', borderwidth=0, relief="flat", foreground="black", background="#4CAF50")
        style.map('Rounded.TButton', background=[('active', '#45a049')])

    def encode_text(self):
        text = self.encryption_text_entry.get()
        encoded = Base64Cipher.encode(text)
        self.show_result(encoded)

    def decode_text(self):
        text = self.decryption_text_entry.get()
        try:
            decoded = Base64Cipher.decode(text)
            self.show_result(decoded)
        except Exception as e:
            self.show_result(f"Error decoding: {str(e)}")

    def show_result(self, message):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert(tk.END, message)
        self.output_text.config(state=tk.DISABLED)

    def encode_from_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'rb') as file:
                data = file.read()
            encoded = base64.b64encode(data).decode('utf-8')
            self.show_result(encoded)

    def decode_from_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r') as file:
                data = file.read()
            try:
                decoded = base64.b64decode(data).decode('utf-8')
                self.show_result(decoded)
            except Exception as e:
                self.show_result(f"Error decoding file: {str(e)}")

    def save_result(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, 'w') as file:
                file.write(self.output_text.get('1.0', tk.END))

def main():
    root = tk.Tk()
    app = Base64CipherUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
