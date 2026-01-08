# Champolion

**Champolion** is a user-friendly GUI application for encrypting and decrypting files and folders using strong cryptography (AES-256 + ephemeral keys). The interface is inspired by classic hacker terminal aesthetics, featuring black backgrounds and electric green text for a sleek, cyberpunk feel.

---

## Features

- Encrypt and decrypt individual files securely  
- Automatically handle file types and restore extensions on decryption  
- Visualize file contents in a preview panel  
- Browse folders and view contents in a dedicated panel  
- Generate, load, and save encryption keys  
- Delete files directly from the interface  
- Responsive GUI with a hacker-terminal aesthetic (black background, green text)  
- Pop-up alerts for incorrect keys or errors  

---

## Screenshots

<img width="446" height="304" alt="image" src="https://github.com/user-attachments/assets/ec1e632a-68f5-4f70-9e87-ec141b6e4240" />


---

## Installation

### Requirements

- Python 3.10+  
- Tkinter (usually included with Python)  
- `cryptography` package  

Install dependencies:

```bash
pip install cryptography
```

### Project Structure
```bash
SecureEncrypt/
│
├── EncriptGUI.py      # Main GUI application
├── Encript_Code.py    # Encryption/decryption logic
├── README.md          # This file
```
### Security Notes

- Uses AES-256 encryption with ephemeral keys
- Keys are displayed in hex for safe copy/paste
- Decryption verifies the file integrity; wrong keys trigger a popup warning
- Only store keys in secure locations

