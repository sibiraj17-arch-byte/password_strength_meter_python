import tkinter as tk
from tkinter import messagebox
import re

# Function to evaluate password strength
def check_password_strength(password):
    # Minimum length check
    if len(password) < 8:
        return "Weak: Password must be at least 8 characters long."
    
    # Check for uppercase, lowercase, digits, and special characters
    if not re.search(r"[A-Z]", password):
        return "Weak: Password must contain at least one uppercase letter."
    
    if not re.search(r"[a-z]", password):
        return "Weak: Password must contain at least one lowercase letter."
    
    if not re.search(r"[0-9]", password):
        return "Weak: Password must contain at least one number."
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Weak: Password must contain at least one special character."
    
    # Check if password is too common
    common_passwords = ['123456', 'password', 'qwerty', 'letmein', '12345']
    if password.lower() in common_passwords:
        return "Weak: Password is too common."

    return "Strong: Password is secure."

# Function for real-time feedback in the UI
def on_password_entry_change(event):
    password = password_entry.get()
    result = check_password_strength(password)
    result_label.config(text=result)

# Function to check passwords from a file
def check_passwords_from_file():
    try:
        with open("passwords.txt", "r") as file:
            passwords = file.readlines()
        
        results = []
        for password in passwords:
            password = password.strip()
            result = check_password_strength(password)
            results.append(f"Password: {password} - {result}")
        
        messagebox.showinfo("Password Strength Results", "\n".join(results))
    except FileNotFoundError:
        messagebox.showerror("Error", "Password file not found!")

# Setting up the Tkinter window
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x300")

# Label for instructions
instruction_label = tk.Label(root, text="Enter your password:")
instruction_label.pack(pady=10)

# Password entry widget
password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack(pady=10)

# Label for displaying password strength
result_label = tk.Label(root, text="Password strength will be shown here.", width=50, height=3)
result_label.pack(pady=10)

# Bind the entry change event to update feedback in real-time
password_entry.bind("<KeyRelease>", on_password_entry_change)

# Button to check passwords from a file
file_check_button = tk.Button(root, text="Check Passwords from File", command=check_passwords_from_file)
file_check_button.pack(pady=10)

# Start the Tkinter event loop
root.mainloop()
