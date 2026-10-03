import tkinter as tk
from tkinter import ttk
import re
import math
import secrets
import string


# -----------------------------
# Password Strength Analyzer
# -----------------------------

COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "iloveyou",
    "abc123",
    "monkey",
    "dragon",
    "football",
    "login",
}


def calculate_entropy(password):
    """Estimate password entropy in bits."""
    if not password:
        return 0

    charset_size = 0

    if re.search(r"[a-z]", password):
        charset_size += 26

    if re.search(r"[A-Z]", password):
        charset_size += 26

    if re.search(r"\d", password):
        charset_size += 10

    if re.search(r"[^a-zA-Z0-9]", password):
        charset_size += 32

    if charset_size == 0:
        return 0

    return len(password) * math.log2(charset_size)


def analyze_password(password):
    """Analyze password and return score, rating, and suggestions."""

    if not password:
        return {
            "score": 0,
            "rating": "No password",
            "entropy": 0,
            "suggestions": ["Enter a password to analyze it."]
        }

    score = 0
    suggestions = []

    # Length
    length = len(password)

    if length >= 16:
        score += 2
    elif length >= 12:
        score += 1
    else:
        suggestions.append("Use at least 12 characters; 16+ is preferable.")

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add lowercase letters.")

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add uppercase letters.")

    # Numbers
    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Add numbers.")

    # Special characters
    if re.search(r"[^a-zA-Z0-9]", password):
        score += 1
    else:
        suggestions.append("Add special characters such as !, @, #, or %.")

    # Common password
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        suggestions.append("This is a commonly used password. Choose something unique.")

    # Repeated characters
    if re.search(r"(.)\1\1", password):
        score -= 1
        suggestions.append("Avoid repeating the same character several times.")

    # Sequential patterns
    sequences = [
        "123456",
        "abcdef",
        "qwerty",
        "password",
    ]

    password_lower = password.lower()

    for sequence in sequences:
        if sequence in password_lower:
            score -= 1
            suggestions.append("Avoid common sequences and predictable words.")
            break

    # Personal/common predictable patterns
    if re.search(r"(19|20)\d{2}", password):
        suggestions.append("Avoid predictable years.")

    # Entropy
    entropy = calculate_entropy(password)

    if entropy < 40:
        rating = "Weak"
    elif entropy < 60:
        rating = "Moderate"
    elif entropy < 80:
        rating = "Strong"
    else:
        rating = "Very Strong"

    # Keep score in range 0-6
    score = max(0, min(score, 6))

    if not suggestions:
        suggestions.append("Good password structure. Make sure it is unique and not reused elsewhere.")

    return {
        "score": score,
        "rating": rating,
        "entropy": entropy,
        "suggestions": suggestions
    }


def generate_password(length=20):
    """Generate a cryptographically secure random password."""

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*()-_=+"

    # Guarantee at least one character from each category
    password_chars = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]

    all_chars = lowercase + uppercase + digits + special

    for _ in range(length - 4):
        password_chars.append(secrets.choice(all_chars))

    # Securely shuffle the characters
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


# -----------------------------
# GUI Functions
# -----------------------------

def check_password():
    password = password_entry.get()

    result = analyze_password(password)

    rating_label.config(text=result["rating"])
    entropy_label.config(
        text=f"Estimated entropy: {result['entropy']:.1f} bits"
    )

    # Progress bar
    progress["value"] = (result["score"] / 6) * 100

    # Colors
    rating = result["rating"]

    if rating == "Weak":
        rating_label.config(foreground="red")
        progress.config(style="Red.Horizontal.TProgressbar")

    elif rating == "Moderate":
        rating_label.config(foreground="orange")
        progress.config(style="Orange.Horizontal.TProgressbar")

    elif rating == "Strong":
        rating_label.config(foreground="green")
        progress.config(style="Green.Horizontal.TProgressbar")

    elif rating == "Very Strong":
        rating_label.config(foreground="darkgreen")
        progress.config(style="Green.Horizontal.TProgressbar")

    else:
        rating_label.config(foreground="black")

    # Suggestions
    suggestions_text.delete("1.0", tk.END)

    for suggestion in result["suggestions"]:
        suggestions_text.insert(tk.END, "• " + suggestion + "\n")


def generate_new_password():
    password = generate_password(20)

    generated_entry.delete(0, tk.END)
    generated_entry.insert(0, password)


def copy_password():
    password = generated_entry.get()

    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        root.update()


def toggle_password():
    if password_entry.cget("show") == "":
        password_entry.config(show="*")
        show_button.config(text="Show")
    else:
        password_entry.config(show="")
        show_button.config(text="Hide")


# -----------------------------
# GUI Setup
# -----------------------------

root = tk.Tk()

root.title("Password Strength Analyzer")
root.geometry("650x600")
root.resizable(False, False)

style = ttk.Style()

style.configure(
    "TButton",
    font=("Arial", 11),
    padding=8
)

style.configure(
    "TLabel",
    font=("Arial", 11)
)

style.configure(
    "Title.TLabel",
    font=("Arial", 22, "bold")
)

style.configure(
    "Red.Horizontal.TProgressbar",
    troughcolor="#eeeeee",
    background="red"
)

style.configure(
    "Orange.Horizontal.TProgressbar",
    troughcolor="#eeeeee",
    background="orange"
)

style.configure(
    "Green.Horizontal.TProgressbar",
    troughcolor="#eeeeee",
    background="green"
)


# Title
title = ttk.Label(
    root,
    text="Password Strength Analyzer",
    style="Title.TLabel"
)

title.pack(pady=(25, 10))


description = ttk.Label(
    root,
    text="Analyze password complexity and generate stronger alternatives."
)

description.pack(pady=(0, 20))


# Password input
input_frame = ttk.Frame(root)
input_frame.pack(pady=5)

ttk.Label(
    input_frame,
    text="Enter Password:"
).grid(row=0, column=0, padx=5)


password_entry = ttk.Entry(
    input_frame,
    width=40,
    show="*"
)

password_entry.grid(row=0, column=1, padx=5)


show_button = ttk.Button(
    input_frame,
    text="Show",
    command=toggle_password
)

show_button.grid(row=0, column=2, padx=5)


# Analyze button
analyze_button = ttk.Button(
    root,
    text="Analyze Password",
    command=check_password
)

analyze_button.pack(pady=15)


# Strength
ttk.Label(
    root,
    text="Password Strength:"
).pack()

rating_label = ttk.Label(
    root,
    text="No password",
    font=("Arial", 16, "bold")
)

rating_label.pack(pady=5)


# Progress bar
progress = ttk.Progressbar(
    root,
    length=450,
    mode="determinate"
)

progress.pack(pady=5)


# Entropy
entropy_label = ttk.Label(
    root,
    text="Estimated entropy: 0 bits"
)

entropy_label.pack(pady=5)


# Suggestions
ttk.Label(
    root,
    text="Suggestions:",
    font=("Arial", 12, "bold")
).pack(pady=(15, 5))


suggestions_text = tk.Text(
    root,
    width=65,
    height=6,
    font=("Arial", 10),
    wrap="word"
)

suggestions_text.pack()


# Password generator
ttk.Label(
    root,
    text="Generate a Strong Password",
    font=("Arial", 12, "bold")
).pack(pady=(20, 8))


generated_frame = ttk.Frame(root)
generated_frame.pack()

generated_entry = ttk.Entry(
    generated_frame,
    width=42
)

generated_entry.grid(row=0, column=0, padx=5)


generate_button = ttk.Button(
    generated_frame,
    text="Generate",
    command=generate_new_password
)

generate_button.grid(row=0, column=1, padx=5)


copy_button = ttk.Button(
    generated_frame,
    text="Copy",
    command=copy_password
)

copy_button.grid(row=0, column=2, padx=5)


# Security note
security_note = ttk.Label(
    root,
    text="Security note: Passwords are analyzed locally and are not stored.",
    foreground="gray"
)

security_note.pack(pady=20)


root.mainloop()
