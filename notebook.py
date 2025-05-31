import tkinter as tk
from tkinter import ttk # Importing ttk for notebook widget
from tkinter import messagebox, filedialog

import hashlib
import os
import json
from cryptography.fernet import Fernet
import base64

# Utility functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(password.ljust(32)[:32].encode())

def encrypt_notebook(password: str, notebook_path: str):
    key = generate_key(password)
    f = Fernet(key)
    try:
        with open(notebook_path, 'rb') as file:
            data = file.read()
        encrypted = f.encrypt(data)
        with open(notebook_path + '.encrypted', 'wb') as file:
            file.write(encrypted)
        return True
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))
        return False

def save_user(username, password):
    user_file = "users.json"
    users = {}
    if os.path.exists(user_file):
        with open(user_file, "r") as f:
            users = json.load(f)
    users[username] = hash_password(password)
    with open(user_file, "w") as f:
        json.dump(users, f)
    return True

# GUI App
root = tk.Tk()
root.title("Notebook Encryptor")
root.geometry("400x400")
root.resizable(False, False)

# Tabs (Login & Register)
notebook = tk.ttk.Notebook(root)
login_frame = tk.Frame(notebook)
register_frame = tk.Frame(notebook)
notebook.add(login_frame, text="Login & Encrypt")
notebook.add(register_frame, text="Register")
notebook.pack(expand=True, fill='both')

# === Login Frame ===
tk.Label(login_frame, text="Username").pack(pady=5)
username_entry = tk.Entry(login_frame, width=30)
username_entry.pack()

tk.Label(login_frame, text="Password").pack(pady=5)
password_entry = tk.Entry(login_frame, show="*", width=30)
password_entry.pack()

tk.Label(login_frame, text="Notebook Path").pack(pady=5)
notebook_path_entry = tk.Entry(login_frame, width=30)
notebook_path_entry.pack()

def browse_file():
    path = filedialog.askopenfilename(
        filetypes=[("All Text Files", "*.txt *.ipynb *.md *.csv"), ("All Files", "*.*")]
    )
    if path:
        notebook_path_entry.delete(0, tk.END)
        notebook_path_entry.insert(0, path)

tk.Button(login_frame, text="Browse", command=browse_file).pack(pady=2)

encrypt_var = tk.IntVar()
tk.Checkbutton(login_frame, text="Encrypt this notebook", variable=encrypt_var).pack()

def submit_login():
    username = username_entry.get().strip()
    password = password_entry.get()
    notebook_path = notebook_path_entry.get()

    if not username or not password:
        messagebox.showwarning("Input Error", "Username and password are required.")
        return

    if encrypt_var.get():
        if not os.path.exists(notebook_path):
            messagebox.showerror("File Error", f"Notebook '{notebook_path}' not found.")
            return
        success = encrypt_notebook(password, notebook_path)
        if success:
            messagebox.showinfo("Success", f"Notebook encrypted:\n{notebook_path}.encrypted")

tk.Button(login_frame, text="Submit", command=submit_login).pack(pady=10)

# === Register Frame ===
tk.Label(register_frame, text="New Username").pack(pady=5)
new_username_entry = tk.Entry(register_frame, width=30)
new_username_entry.pack()

tk.Label(register_frame, text="New Password").pack(pady=5)
new_password_entry = tk.Entry(register_frame, show="*", width=30)
new_password_entry.pack()

def register_user():
    username = new_username_entry.get().strip()
    password = new_password_entry.get()

    if not username or not password:
        messagebox.showwarning("Input Error", "Both fields are required.")
        return

    save_user(username, password)
    messagebox.showinfo("Success", f"User '{username}' registered.")

tk.Button(register_frame, text="Create User", command=register_user).pack(pady=10)

def create_notebook():
    path = filedialog.asksaveasfilename(
        defaultextension=".ipynb",
        filetypes=[("Jupyter Notebook", "*.ipynb")],
        title="Create New Notebook"
    )
    if path:
        # Minimal notebook structure
        notebook_content = {
            "cells": [],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(notebook_content, f, indent=2)
        notebook_path_entry.delete(0, tk.END)
        notebook_path_entry.insert(0, path)
        messagebox.showinfo("Notebook Created", f"Created notebook:\n{path}")

tk.Button(login_frame, text="Create Notebook", command=create_notebook).pack(pady=2)

def edit_notebook():
    path = notebook_path_entry.get()
    if not os.path.exists(path):
        messagebox.showerror("File Error", f"File '{path}' not found.")
        return

    # Open a new window for editing
    editor_win = tk.Toplevel(root)
    editor_win.title(f"Editing: {os.path.basename(path)}")
    editor_win.geometry("600x600")

    text_widget = tk.Text(editor_win, wrap="none")
    text_widget.pack(expand=True, fill="both")

    # Load file content
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    text_widget.insert("1.0", content)

    def save_edits():
        try:
            # If it's a notebook, validate JSON before saving
            if path.endswith(".ipynb"):
                json.loads(text_widget.get("1.0", tk.END))
            with open(path, "w", encoding="utf-8") as f:
                f.write(text_widget.get("1.0", tk.END).strip())
            messagebox.showinfo("Saved", f"File '{path}' saved.")
        except Exception as e:
            messagebox.showerror("Save Error", f"Error: {e}")

    tk.Button(editor_win, text="Save", command=save_edits).pack(pady=5)

tk.Button(login_frame, text="Edit Notebook", command=edit_notebook).pack(pady=2)

root.mainloop()
