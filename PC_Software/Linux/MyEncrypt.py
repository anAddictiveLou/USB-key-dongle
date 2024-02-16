import tkinter as tk
from tkinter import filedialog, messagebox
import pyAesCrypt
import os
from os import stat, remove

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MyEncrypt")

        self.file_path = ""
        self.password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        self.create_widgets()

    def create_widgets(self):
        # File Selection
        tk.Label(self.root, text="Select File:").grid(row=0, column=0, padx=10, pady=5)
        tk.Button(self.root, text="Browse", command=self.browse_file).grid(row=0, column=1, padx=10, pady=5)

        # Directory Display
        tk.Label(self.root, text="File Path:").grid(row=1, column=0, padx=10, pady=5)
        self.directory_text = tk.Entry(self.root, state='readonly', width=40)
        self.directory_text.grid(row=1, column=1, padx=10, pady=5, columnspan=2)

        # Password Input
        tk.Label(self.root, text="Password:").grid(row=2, column=0, padx=10, pady=5)
        tk.Entry(self.root, textvariable=self.password, show="*").grid(row=2, column=1, padx=10, pady=5)

        # Confirm Password Input
        tk.Label(self.root, text="Confirm Password:").grid(row=3, column=0, padx=10, pady=5)
        tk.Entry(self.root, textvariable=self.confirm_password, show="*").grid(row=3, column=1, padx=10, pady=5)

        # Encrypt Button
        tk.Button(self.root, text="Encrypt", command=self.encrypt_file).grid(row=4, column=0, columnspan=2, pady=10)

        # Copyright Information
        tk.Label(self.root, text="© 2024 Thesis Graduation Project.", font=("Helvetica", 8), fg="gray").grid(row=5, column=0, columnspan=3, pady=5)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if self.file_path:
            file_directory = self.file_path
            self.directory_text.config(state='normal')
            self.directory_text.delete(0, tk.END)
            self.directory_text.insert(tk.END, file_directory)
            self.directory_text.config(state='readonly')

    def encrypt_file(self):
        if not self.file_path:
            self.show_message("Error", "Please select a file.")
            return

        password = self.password.get()
        confirm_password = self.confirm_password.get()

        if not password or not confirm_password:
            self.show_message("Error", "Please enter and confirm the password.")
            return

        if password != confirm_password:
            self.show_message("Error", "Passwords do not match.")
            return

        try:
            bufferSize = 64 * 1024
            encrypted_file_path = self.file_path + ".aes"
            pyAesCrypt.encryptFile(self.file_path, encrypted_file_path, password, bufferSize)
            if os.path.isfile(encrypted_file_path):
                remove(self.file_path)
            self.show_message("Success", f"File encrypted successfully!\nEncrypted file saved at:\n{encrypted_file_path}")
            
        except Exception as e:
            self.show_message("Error", f"Encryption failed.\n{str(e)}")
        

    def show_message(self, title, message):
        messagebox.showinfo(title, message)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
