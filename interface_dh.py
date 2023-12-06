import tkinter as tk
from tkinter import filedialog, simpledialog
from getpass import getpass
from tkinter import messagebox
from Crypto.Protocol.KDF import PBKDF2
# from Triple_Des import encryptor, decryptor
from main import encrypt_image, decrypt_image, encrypt_image_3Des, decrypt_image_3Des
import os


class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Triple-DES Image Encryptor")

        # Variables
        self.file_path_var = tk.StringVar()
        self.choice_var = tk.StringVar(value="1")
        self.algo_var = tk.StringVar(value="DES")

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

        # Drop down menu for algorithm
        algo_label = tk.Label(self.root, text="Choose Algorithm:")
        algo_label.pack(pady=10)
        algo_menu = tk.OptionMenu(self.root, self.algo_var, "DES", "Triple-DES")
        algo_menu.pack()
        
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

        # Process Button
        process_button = tk.Button(
            self.root, text="Encrypt/Decrypt", command=self.process_image
        )
        process_button.pack(pady=10)

    def get_password(self, c):
        if c == "1":
            with open('D:\\Crypto Project\\alice-shared-key.txt','rb') as file:
                password=file.read()
        else:
            with open('D:\\Crypto Project\\bob-shared-key.txt','rb') as file:
                password=file.read()
        password = password.decode('latin')
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
        algo = self.algo_var.get()
        # password = self.password
        # password = getpass(prompt="Enter password:")

        if choice == "1" and algo == "DES":
            try:
                password = self.get_password(choice)
                output_path = "encrypted_" + file_path
                encrypt_image(file_path, password, output_path)
                messagebox.showinfo("Success", "Encryption successful!")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
        elif choice == "2" and algo == "DES":
            try:
                password = self.get_password(choice)
                output_path = "decrypted_" + file_path
                decrypt_image(file_path, password, output_path)
                messagebox.showinfo("Success", "Decryption successful!")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
        elif choice == "1" and algo == "Triple-DES":
            try:
                password = self.get_password(choice)
                output_path = "encrypted_" + file_path
                encrypt_image_3Des(file_path, password, output_path)
                messagebox.showinfo("Success", "Encryption successful!")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
        elif choice == "2" and algo == "Triple-DES":
            try:
                password = self.get_password(choice)
                output_path = "decrypted_" + file_path
                decrypt_image_3Des(file_path, password, output_path)
                messagebox.showinfo("Success", "Decryption successful!")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()
