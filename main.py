from algorithms.caesar_cipher import CaesarCipher, CaesarCipherUI
from algorithms.substitution_cipher import SubstitutionCipher, SubstitutionCipherUI
from algorithms.one_time_pad import OneTimePadUI
from algorithms.base64 import Base64Cipher,Base64CipherUI
import tkinter as tk
from tkinter import ttk
from tkinter.font import Font
from tkinter import Canvas

# Custom rounded button class
class RoundedButton(Canvas):
    def __init__(self, parent, width, height, corner_radius, text="", command=None, bg_color="#fff", text_color="#fff", font=None, **kwargs):
        Canvas.__init__(self, parent, borderwidth=0, highlightthickness=0, width=width, height=height, **kwargs)
        self.command = command

        # Draw a rounded rectangle
        self.create_oval((0, 0, corner_radius * 2, corner_radius * 2), fill=bg_color)
        self.create_oval((0, height - corner_radius * 2, corner_radius * 2, height), fill=bg_color)
        self.create_oval((width - corner_radius * 2, 0, width, corner_radius * 2), fill=bg_color)
        self.create_oval((width - corner_radius * 2, height - corner_radius * 2, width, height), fill=bg_color)
        self.create_rectangle((0, corner_radius, width, height - corner_radius), fill=bg_color, outline=bg_color)
        self.create_rectangle((corner_radius, 0, width - corner_radius, height), fill=bg_color, outline=bg_color)

        # Add text in the middle of the button
        self.create_text(width / 2, height / 2, text=text, fill=text_color, font=font)

        # Bind the click event
        self.bind("<Button-1>", self._on_click)

    def _on_click(self, event):
        if self.command:
            self.command()

# Main application class
class EncryptionApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Crypto Project")
        self.master.geometry("1920x1080")

        # Custom fonts
        self.title_font = Font(family="Helvetica", size=30, weight="bold")
        self.button_font = Font(family="Helvetica", size=18, weight="bold")

        # Sidebar frame
        self.sidebar = ttk.Frame(master, width=200, style='Sidebar.TFrame')
        self.sidebar.grid(row=0, column=0, sticky="ns")  # 'ns' makes it expand vertically

        # Main frame
        self.main_frame = ttk.Frame(master)
        self.main_frame.grid(row=0, column=1, sticky="nsew")  # 'nsew' makes it expand in all directions

        self.create_sidebar()
        self.create_home_screen()

        # Configure the grid to allow sidebar to expand full height
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_columnconfigure(0, weight=0)  # Sidebar column doesn't expand horizontally
        self.master.grid_columnconfigure(1, weight=1)  # Main content column does expand horizontally

        self.sidebar_label.bind("<Button-1>", lambda event: self.go_to_home_screen())

    def go_to_home_screen(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        self.create_home_screen()
        
    def create_sidebar(self):
        self.sidebar_label = ttk.Label(self.sidebar, text="Algorithms", foreground="black",font=self.title_font,)
        self.sidebar_label.pack(pady=30)

        self.algorithm_options = ["Caesar Cipher", "One Time Pad", "Substitution Cipher", "Base64"]
        self.algorithm_colors = ["#575", "#33F", "#5733FF", "#F97"]  # Example colors
        self.algorithm_fonts = [Font(family="Helvetica", size=16, weight="bold") for _ in range(len(self.algorithm_options))]
        self.algorithm_text_colors = ["white", "white", "white", "white"]  # Example text colors
        self.algorithm_buttons = []

        for i, algo in enumerate(self.algorithm_options):
            button = RoundedButton(
                self.sidebar, width=250, height=90, corner_radius=16, text=algo, command=lambda a=algo: self.show_algorithm_screen(a),
                  bg_color=self.algorithm_colors[i], text_color=self.algorithm_text_colors[i], font=self.algorithm_fonts[i])
            button.pack(pady=30, padx=15)

    def create_home_screen(self):
        self.home_label = ttk.Label(self.main_frame, text="Welcome to Crypto Project!", font=self.title_font)
        self.home_label.pack(pady=30)

        description_text = "In this project, we have developed a sophisticated application aimed at securing sensitive data through encryption and decryption processes.Our application provides users with a seamless experience, offering a user-friendly graphical interface that simplifies the otherwise complex task of encrypting and decrypting files.\n\nWith our application, users can encrypt and decrypt their files using a selection of four robust encryption algorithms. Whether it's encrypting personal documents or decrypting sensitive files, our application ensures data confidentiality through state-of-the-art encryption techniques.\n\nOne of the standout features of our application is its versatility in handling various types of data. Users have the option to input plain text directly into the application or select files from their system for encryption or decryption. This flexibility allows users to safeguard their data in the format that suits them best.\n\nThe heart of our application lies in its intuitive graphical user interface (GUI).Developed using the Tkinter library, our GUI provides users with a visually appealing and easy-to-navigate platform. Key elements of the GUI include a text area for inputting plain text, file upload/download buttons for seamless file management, and dedicated encryption/decryption controls for initiating the encryption and decryption processes.\n\nMoreover, our application goes beyond mere functionality by prioritizing user experience. We have incorporated features such as the ability for users to specify keys or passphrases for encryption/decryption, ensuring an added layer of security and customization. \n\nIn summary, our project delivers a fully functional encryption/decryption application with a focus on user accessibility and data security. By combining powerful encryption algorithms with an intuitive GUI, we aim to provide users with a reliable solution for safeguarding their sensitive information."
        self.description_label = ttk.Label(self.main_frame, text=description_text, font=("Helvetica", 15), wraplength=1000)
        self.description_label.pack(pady=10)

    def show_algorithm_screen(self, algorithm):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        if algorithm == "Caesar Cipher":
            self.caesar_ui = CaesarCipherUI(self.main_frame)
        
        elif algorithm == "One Time Pad":
            self.otp_ui = OneTimePadUI(self.main_frame)

        elif algorithm == "Substitution Cipher":
            self.substitution_ui = SubstitutionCipherUI(self.main_frame)

        elif algorithm == "Base64":
            self.base64_ui = Base64CipherUI(self.main_frame)

def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
