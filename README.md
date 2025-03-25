# Intelligent Password Strength Management 🔒

## Overview
**Intelligent Password Strength Management** is a security tool designed to help users create, evaluate, and manage strong passwords. It integrates real-time password strength analysis, breach detection via the *Have I Been Pwned* API, and AES-encrypted password storage to enhance security.

## Features 🚀
✅ **Password Strength Meter** – Real-time evaluation using entropy and the `zxcvbn` library.  
✅ **Breach Detection** – Checks if passwords have been compromised using *Have I Been Pwned* API.  
✅ **Secure Password Generator** – Creates strong, customizable passwords resistant to brute-force attacks.  
✅ **Encryption & Secure Export** – Uses AES encryption to safely store passwords.  
✅ **User-Friendly GUI** – Built with Tkinter for an intuitive experience.  

## Tech Stack 🛠️
- **Python 3.x** – Core programming language  
- **zxcvbn** – Password strength analysis  
- **cryptography** – Encryption & decryption for secure storage  
- **Tkinter** – Graphical User Interface  
- **Requests** – API calls for breach detection  

## Installation 🏗️

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/password-strength-manager.git
cd password-strength-manager
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Run the Application
```bash
python main.py
```

## Usage 💡
1. **Enter a password** to check its strength.
2. Get **real-time feedback** on its security.
3. **Generate a strong password** with customizable parameters.
4. **Check if your password is breached** using the Have I Been Pwned API.
5. **Securely export passwords** with AES encryption.

## Contributing 🤝
Contributions are welcome! If you have suggestions or want to enhance the project, feel free to submit a pull request.  

## License 📜
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact 📬
For any questions or feedback, feel free to reach out:  
👤 **Aditya Nayak**  
📧 Email: aditya.nayak2021@vitstudent.ac.in  
