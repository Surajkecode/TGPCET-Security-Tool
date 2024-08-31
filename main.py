import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
import base64
import time


# Generate a key for encryption from a password
def generate_key(password):
    return base64.urlsafe_b64encode(password.ljust(32)[:32].encode())


# Compute SHA-256 hash of a file
def compute_hash(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


# Encrypt a file and save it to a new location with a hash code
def encrypt_file(file_path, key, output_path):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(output_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

    # Compute hash code of the encrypted file
    hash_code = compute_hash(output_path)
    # Rename file to include hash code
    encrypted_file_path = output_path + f'_{hash_code}.enc'
    os.rename(output_path, encrypted_file_path)
    return encrypted_file_path, hash_code


# Decrypt a file and save it to a new location with the original name
def decrypt_file(file_path, key, output_path):
    fernet = Fernet(key)
    with open(file_path, 'rb') as encrypted_file:
        encrypted = encrypted_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(output_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

    # Optionally rename file if needed (e.g., remove hash code)
    decrypted_file_path = output_path
    os.rename(output_path, decrypted_file_path)
    return decrypted_file_path


# Encrypt all files in a folder and save them to a new location with a hash code
def encrypt_folder(folder_path, key, output_folder):
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, folder_path)
            output_path = os.path.join(output_folder, relative_path + '.enc')  # Add .enc extension
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            encrypted_file_path, hash_code = encrypt_file(file_path, key, output_path)
            print(f"Encrypted: {file_path} -> {encrypted_file_path} with hash {hash_code}")


# Decrypt all files in a folder and save them to a new location
def decrypt_folder(folder_path, key, output_folder):
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file_path.endswith('.enc'):
                relative_path = os.path.relpath(file_path, folder_path)
                output_path = os.path.join(output_folder,
                                           relative_path.replace('.enc', '.dec'))  # Remove .enc extension
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                decrypt_file(file_path, key, output_path)
                print(f"Decrypted: {file_path} -> {output_path}")


# Encrypt text
def encrypt_text(text, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(text.encode())
    return encrypted.decode()


# Decrypt text
def decrypt_text(encrypted_text, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_text.encode())
    return decrypted.decode()


# Show interactive processing animation
def show_processing():
    processing_label.config(text="Processing...")
    root.update_idletasks()
    time.sleep(2)  # Simulate processing time
    processing_label.config(text="")


# Perform text encryption
def perform_text_encryption():
    password = entry_password.get().strip()
    key = generate_key(password)
    text = entry_text.get("1.0", tk.END).strip()
    if text:
        show_processing()  # Show processing animation
        encrypted_text = encrypt_text(text, key)
        entry_encrypted_text.delete("1.0", tk.END)
        entry_encrypted_text.insert(tk.END, encrypted_text)
        messagebox.showinfo("Success", "Text encrypted successfully.")


# Perform text decryption
def perform_text_decryption():
    password = entry_password.get().strip()
    key = generate_key(password)
    encrypted_text = entry_encrypted_text.get("1.0", tk.END).strip()
    if encrypted_text:
        show_processing()  # Show processing animation
        decrypted_text = decrypt_text(encrypted_text, key)
        entry_text.delete("1.0", tk.END)
        entry_text.insert(tk.END, decrypted_text)
        messagebox.showinfo("Success", "Text decrypted successfully.")


# Perform file encryption or decryption based on user choice
def perform_file_encryption():
    password = entry_password.get().strip()
    key = generate_key(password)

    file_types = [('Allowed files', '*.pdf;*.txt;*.ppt;*.pptx')]
    if folder_var.get():
        folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
        if folder_path:
            output_folder = filedialog.askdirectory(title="Select Output Folder")
            if output_folder:
                encrypt_folder(folder_path, key, output_folder)
                messagebox.showinfo("Success", "Folder encrypted successfully.")
    else:
        file_path = filedialog.askopenfilename(filetypes=file_types, title="Select File to Encrypt")
        if file_path:
            output_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                       filetypes=[("Encrypted files", "*.enc")],
                                                       title="Save Encrypted File As")
            if output_path:
                show_processing()  # Show processing animation
                encrypted_file_path, hash_code = encrypt_file(file_path, key, output_path)
                messagebox.showinfo("Success", f"File encrypted successfully.\nHash code: {hash_code}")


def perform_file_decryption():
    password = entry_password.get().strip()
    key = generate_key(password)

    file_types = [('Encrypted files', '*.enc')]
    if folder_var.get():
        folder_path = filedialog.askdirectory(title="Select Folder to Decrypt")
        if folder_path:
            output_folder = filedialog.askdirectory(title="Select Output Folder")
            if output_folder:
                decrypt_folder(folder_path, key, output_folder)
                messagebox.showinfo("Success", "Folder decrypted successfully.")
    else:
        file_path = filedialog.askopenfilename(filetypes=file_types, title="Select Encrypted File to Decrypt")
        if file_path:
            output_path = filedialog.asksaveasfilename(defaultextension=".dec",
                                                       filetypes=[("Decrypted files", "*.dec")],
                                                       title="Save Decrypted File As")
            if output_path:
                show_processing()  # Show processing animation
                decrypted_file_path = decrypt_file(file_path, key, output_path)
                messagebox.showinfo("Success", "File decrypted successfully.")


# Create the main window
root = tk.Tk()
root.title("TGPCET SECURITY")

# Set the color scheme
root.configure(bg='black')
frame = tk.Frame(root, bg='black')
frame.grid(row=0, column=0, padx=20, pady=20)

# Title Label
title_label = tk.Label(root, text="TGPCET SECURITY", font=("Helvetica", 18, "bold"), bg='black', fg='green')
title_label.grid(row=0, column=0, padx=20, pady=10)

# Create and place the widgets
tk.Label(frame, text="Password:", bg='black', fg='green').grid(row=0, column=0, padx=10, pady=10, sticky='w')
entry_password = tk.Entry(frame, width=50, show="*", bg='black', fg='green', insertbackground='green')
entry_password.grid(row=0, column=1, padx=10, pady=10)
entry_password.insert(0, "suraj")  # Default password for convenience

folder_var = tk.BooleanVar()
folder_checkbox = tk.Checkbutton(frame, text="Encrypt/Decrypt Folder", variable=folder_var, bg='black', fg='green',
                                 selectcolor='black')
folder_checkbox.grid(row=1, column=1, padx=10, pady=10, sticky='w')

# File Encryption/Decryption Buttons
encrypt_file_button = tk.Button(frame, text="Encrypt File", command=perform_file_encryption, bg='black', fg='green')
encrypt_file_button.grid(row=2, column=0, padx=10, pady=10)

decrypt_file_button = tk.Button(frame, text="Decrypt File", command=perform_file_decryption, bg='black', fg='green')
decrypt_file_button.grid(row=2, column=1, padx=10, pady=10, sticky='w')

# Text Encryption/Decryption Buttons
encrypt_text_button = tk.Button(frame, text="Encrypt Text", command=perform_text_encryption, bg='black', fg='green')
encrypt_text_button.grid(row=5, column=0, padx=10, pady=10)

decrypt_text_button = tk.Button(frame, text="Decrypt Text", command=perform_text_decryption, bg='black', fg='green')
decrypt_text_button.grid(row=5, column=1, padx=10, pady=10, sticky='w')

# Text Entry and Output
tk.Label(frame, text="Text to Encrypt/Decrypt:", bg='black', fg='green').grid(row=3, column=0, padx=10, pady=10,
                                                                              sticky='w')
entry_text = tk.Text(frame, width=60, height=10, bg='black', fg='green', insertbackground='green')
entry_text.grid(row=3, column=1, padx=10, pady=10)

tk.Label(frame, text="Encrypted Text:", bg='black', fg='green').grid(row=4, column=0, padx=10, pady=10, sticky='w')
entry_encrypted_text = tk.Text(frame, width=60, height=10, bg='black', fg='green', insertbackground='green')
entry_encrypted_text.grid(row=4, column=1, padx=10, pady=10)

# Processing animation label
processing_label = tk.Label(frame, text="", bg='black', fg='green')
processing_label.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

# Start the GUI event loop
root.mainloop()
