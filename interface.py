import tkinter as tk
from tkinter import filedialog, simpledialog
from getpass import getpass
from tkinter import messagebox
from Crypto.Protocol.KDF import PBKDF2
from Triple_Des import encryptor, decryptor
import os


class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Triple-DES Image Encryptor")

        # Variables
        self.file_path_var = tk.StringVar()
        self.choice_var = tk.StringVar(value="1")

        # UI components
        self.create_widgets()

    def create_widgets(self):
        # File Entry
        file_label = tk.Label(self.root, text="File Path:")
        file_label.pack(pady=10)

        file_entry = tk.Entry(self.root, textvariable=self.file_path_var, width=50)
        file_entry.pack(pady=5)

        browse_button = tk.Button(self.root, text="Browse", command=self.browse_file)
        browse_button.pack(pady=5)

        # Choice (Encryption/Decryption)
        choice_label = tk.Label(self.root, text="Choose Action:")
        choice_label.pack(pady=10)

        encryption_radio = tk.Radiobutton(
            self.root, text="Encryption", variable=self.choice_var, value="1"
        )
        encryption_radio.pack()

        decryption_radio = tk.Radiobutton(
            self.root, text="Decryption", variable=self.choice_var, value="2"
        )
        decryption_radio.pack()

        # Password Entry
        # password_label = tk.Label(self.root, text="Password:")
        # password_label.pack(pady=10)

        # password_entry = tk.Entry(self.root, show="*")
        # password_entry.pack(pady=5)

        # password = simpledialog.askstring("Password", "Enter password:", show="*")

        # Process Button
        process_button = tk.Button(
            self.root, text="Encrypt/Decrypt", command=self.process_image
        )
        process_button.pack(pady=10)

    def get_password(self):
        password = simpledialog.askstring("Password", "Enter password:", show="*")
        return password

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.gif")]
        )
        if file_path:
            self.file_path_var.set(file_path)

    def process_image(self):
        file_path = self.file_path_var.get()
        file_path = os.path.basename(file_path)
        choice = self.choice_var.get()
        # password = self.password
        # password = getpass(prompt="Enter password:")

        if choice == "1":
            try:
                password = self.get_password()
                encryptor(file_path, password)
                messagebox.showinfo("Success", "Encryption successful!")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
        elif choice == "2":
            try:
                password = self.get_password()
                decryptor(file_path, password)
                messagebox.showinfo("Success", "Decryption successful!")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()
