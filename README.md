# Blockchain-Backed Image Steganography Tool

## Overview
This project implements **Image Steganography** with **AES encryption** and **Blockchain** for secure message storage. It allows users to hide text inside an image using encryption and retrieve it securely using a password.

## Features
- **Encode Text into Images**: Hide secret messages inside an image using LSB steganography.
- **AES Encryption**: Encrypt messages before embedding them in the image.
- **Password Protection**: Users must enter a password to encode or decode messages.
- **Blockchain for Integrity**: Ensures the integrity of hidden messages using blockchain hashing.
- **GUI with Tkinter**: User-friendly graphical interface for encoding and decoding messages.

## Requirements
Ensure you have the following dependencies installed:
```bash
pip install pillow cryptography tkinter hashlib
```

## How to Run
1. **Run the Application**:
   ```bash
   python main.py
   ```
    **NOTE: Password to access the application is "12345678"**

2. **Encoding a Message**:
   - Select an image file.
   - Enter a secret message.
   - Choose a password for encryption.
   - Save the new stego-image.

3. **Decoding a Message**:
   - Open the stego-image.
   - Enter the password to retrieve the hidden message.


## Security Measures
- **AES-256 Encryption**: Ensures messages remain secure inside the image.
- **Blockchain Hashing**: Prevents tampering by verifying the integrity of encoded messages.
- **Password Protection**: Ensures only authorized users can decode messages.

## Future Enhancements
- Support for **multiple encryption methods** (RSA, ECC).
- Implement **image hashing** for additional security.
- Web-based interface for remote access.


