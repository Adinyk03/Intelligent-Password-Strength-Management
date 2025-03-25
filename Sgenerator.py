import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import re
import random
import string
import logging
import hashlib
from functools import lru_cache
from math import log2
from cryptography.fernet import Fernet
from zxcvbn import zxcvbn
import requests

logging.basicConfig(
    filename='password_checker.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Generate encryption key for secure export
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

class Wordlist:
    """Class to handle wordlists."""

    _cache = {}

    def __init__(self, file_path):
        self.file_path = file_path
        self.words = self.load_wordlist()

    def load_wordlist(self):
        """Load wordlist from file."""
        if self.file_path in self._cache:
            return self._cache[self.file_path]

        try:
            with open(self.file_path, 'r', encoding='utf-8') as file:
                wordlist = [line.strip() for line in file]
                self._cache[self.file_path] = wordlist
                return wordlist
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Error: File '{self.file_path}' not found.") from e
        except Exception as e:
            raise RuntimeError(f"Error loading wordlist from '{self.file_path}': {str(e)}") from e

    def is_word_in_list(self, word):
        return word in self.words


class StrengthResult:
    """Class to store password strength check results."""

    def __init__(self, strength: str, score: int, message: str, entropy: float):
        self.strength = strength
        self.score = score
        self.message = message
        self.entropy = entropy


class PasswordStrength:
    """Class to handle password strength checking and related operations."""

    def __init__(self, weak_wordlist_path: str = "./weak_passwords.txt",
                 banned_wordlist_path: str = "./banned_passwords.txt"):
        self.weak_wordlist = (Wordlist(weak_wordlist_path)
                              if weak_wordlist_path else None)
        self.banned_wordlist = (Wordlist(banned_wordlist_path)
                                if banned_wordlist_path else None)
        self.min_password_length = 12
        self.strength_mapping = {
            0: "Very Weak",
            1: "Weak",
            2: "Moderate",
            3: "Strong",
            4: "Very Strong"
        }

    def get_entropy_explanation(self, entropy):
        """Provide an explanation of entropy."""
        if entropy < 28:
            return "Very weak: Easily guessable."
        elif entropy < 36:
            return "Weak: May be cracked quickly."
        elif entropy < 60:
            return "Moderate: Somewhat secure but can be improved."
        elif entropy < 128:
            return "Strong: A secure password for most uses."
        else:
            return "Very Strong: Extremely secure and resistant to attacks."

    def calculate_entropy(self, password):
        """Calculate the entropy of a password."""
        pool_size = 0
        if re.search(r'[a-z]', password):
            pool_size += 26
        if re.search(r'[A-Z]', password):
            pool_size += 26
        if re.search(r'\d', password):
            pool_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            pool_size += 32
        entropy = len(password) * log2(pool_size) if pool_size > 0 else 0
        return round(entropy, 2)

    def check_password_breach(self, password):
        """Check if the password is found in a data breach using Have I Been Pwned API."""
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)
        if response.status_code == 200:
            hashes = response.text.splitlines()
            for h in hashes:
                if h.startswith(suffix):
                    return True
        return False

    @lru_cache(maxsize=1000)
    def check_password_strength(self, password: str) -> StrengthResult:
        """Check the strength of a given password."""
        if len(password) < self.min_password_length:
            return StrengthResult("Too short", 0, "Password should be at least 12 characters long.", 0)

        if self.weak_wordlist and self.weak_wordlist.is_word_in_list(password):
            return StrengthResult("Weak", 0, "Password is commonly used and easily guessable.", 0)

        if self.banned_wordlist and self.banned_wordlist.is_word_in_list(password):
            return StrengthResult("Banned", 0,
                                  "This password is not allowed, as it is commonly found in data leaks.", 0)

        if self.check_password_breach(password):
            return StrengthResult("Breach Detected", 0,
                                  "This password has been involved in a data breach. Avoid using it.", 0)

        entropy = self.calculate_entropy(password)
        password_strength = zxcvbn(password)
        score = password_strength["score"]
        strength = self.strength_mapping[score]
        complexity_issues = []
        if not re.search(r'[A-Z]', password):
            complexity_issues.append("uppercase letter")
        if not re.search(r'[a-z]', password):
            complexity_issues.append("lowercase letter")
        if not re.search(r'\d', password):
            complexity_issues.append("number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            complexity_issues.append("special character")

        if complexity_issues:
            return StrengthResult("Weak", score,
                                  f"Password lacks complexity. Missing: {', '.join(complexity_issues)}.", entropy)

        if score >= 3:
            return StrengthResult(strength, score,
                                  f"Password meets all the requirements. Score: {score}/4. Entropy: {entropy} bits",
                                  entropy)

        suggestions = password_strength["feedback"]["suggestions"]
        return StrengthResult(strength, score,
                              f"Password is {strength.lower()}. Suggestions: {', '.join(suggestions)}", entropy)

    def generate_random_password(self, length=16):
        """Generate a random password."""
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))


class PasswordStrengthGUI:
    """GUI class for Password Strength Checker."""

    def __init__(self, master):
        # GUI setup code as before
        pass


# GUI initialization as before

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthGUI(root)
    root.mainloop()


class PasswordStrengthGUI:
    """GUI class for Password Strength Checker."""

    def __init__(self, master):
        self.master = master
        master.title("Password Strength Checker")

        self.password_strength = PasswordStrength()

        # Label for setting minimum password length
        self.min_length_label = tk.Label(master, text="Minimum Password Length:")
        self.min_length_label.pack()

        # Spinbox for setting minimum password length
        self.min_length_spinbox = tk.Spinbox(
            master, from_=4, to=64, width=5, command=self.update_min_length
        )
        self.min_length_spinbox.pack()
        self.min_length_spinbox.delete(0, tk.END)
        self.min_length_spinbox.insert(0, str(self.password_strength.min_password_length))

        # Label for entering password
        self.label = tk.Label(master, text="Enter password:")
        self.label.pack()

        # Entry field for password
        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.pack()
        self.password_entry.bind('<KeyRelease>', self.update_strength_meter)

        # Progress bar for password strength
        self.strength_meter = ttk.Progressbar(master, length=200, mode='determinate')
        self.strength_meter.pack()

        # Label to display password strength
        self.strength_label = tk.Label(master, text="Password Strength: ")
        self.strength_label.pack()

        # Label to display entropy value
        self.entropy_label = tk.Label(master, text="Entropy: ")
        self.entropy_label.pack()

        # Label to display entropy explanation
        self.entropy_explanation_label = tk.Label(master, text="Entropy Explanation: ", wraplength=300, justify="left")
        self.entropy_explanation_label.pack()

        # Label to display feedback for password
        self.feedback_label = tk.Label(master, text="", wraplength=300, justify="left")
        self.feedback_label.pack()

        # Button to check password strength
        self.check_button = tk.Button(master, text="Check Strength", command=self.check_password)
        self.check_button.pack()

        # Button to generate a strong password
        self.generate_button = tk.Button(master, text="Generate Strong Password", command=self.generate_password)
        self.generate_button.pack()

        # Button to export the password securely
        self.export_button = tk.Button(master, text="Export Password", command=self.export_password)
        self.export_button.pack()

        # Button to quit the application
        self.quit_button = tk.Button(master, text="Quit", command=master.quit)
        self.quit_button.pack()

    def update_min_length(self):
        """Update the minimum password length based on user input."""
        try:
            min_length = int(self.min_length_spinbox.get())
            if min_length >= 4:
                self.password_strength.min_password_length = min_length
            else:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Input", "Minimum length must be an integer of at least 4.")

    def update_strength_meter(self, event=None):
        """Update progress bar and display feedback based on password strength."""
        password = self.password_entry.get()
        if not password:
            self.strength_meter['value'] = 0
            self.strength_label.config(text="Password Strength: ")
            self.entropy_label.config(text="Entropy: ")
            self.entropy_explanation_label.config(text="Entropy Explanation: ")
            self.feedback_label.config(text="")
            return

        result = self.password_strength.check_password_strength(password)
        self.strength_meter['value'] = result.score * 25  # Map score (0-4) to 0-100
        self.strength_label.config(text=f"Password Strength: {result.strength}")
        self.entropy_label.config(text=f"Entropy: {result.entropy} bits")
        entropy_explanation = self.password_strength.get_entropy_explanation(result.entropy)
        self.entropy_explanation_label.config(text=f"Entropy Explanation: {entropy_explanation}")
        self.feedback_label.config(text=result.message)

    def check_password(self):
        """Check the password entered and display the strength."""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password.")
            return

        result = self.password_strength.check_password_strength(password)
        self.strength_label.config(text=f"Password Strength: {result.strength}")
        self.entropy_label.config(text=f"Entropy: {result.entropy} bits")
        entropy_explanation = self.password_strength.get_entropy_explanation(result.entropy)
        self.entropy_explanation_label.config(text=f"Entropy Explanation: {entropy_explanation}")
        self.feedback_label.config(text=result.message)
        logging.info(f"Password checked: Strength={result.strength}, Entropy={result.entropy}")

    def generate_password(self):
        """Generate and display a strong random password."""
        password = self.password_strength.generate_random_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.update_strength_meter()

        # Prompt user to copy the password to clipboard
        if messagebox.askyesno("Copy to Clipboard", "Do you want to copy the generated password to the clipboard?"):
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            self.master.update()  # Ensure the clipboard is updated
            messagebox.showinfo("Copied", "Password has been copied to the clipboard.")

    def export_password(self):
        """Export the entered password securely."""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("No Password", "Please generate or enter a password before exporting.")
            return

        encrypted_password = cipher_suite.encrypt(password.encode())
        file_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                 filetypes=[("Encrypted Files", "*.enc")])
        if file_path:
            with open(file_path, 'wb') as file:
                file.write(encrypted_password)
            messagebox.showinfo("Export Successful", "Password has been securely saved!")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthGUI(root)
    root.mainloop()
