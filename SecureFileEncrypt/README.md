# SecureFileEncrypt 🕵️‍♂️🔐

This project simulates how real-world ransomware might behave, including AES encryption (CBC mode), SHA-256 file 
hashing, stealth mode operation, and random IV usage.

---

## 🧠 Why I Built This

After a conversation with my buddy Kishore about malware analysis, I wanted to **dive headfirst into cyber**, soaking 
up as much knowledge as I could from where I’m at.

Even though I'm still going through Pwn College (Linux module), this was my first attempt at simulating real malware 
behavior — not to build malicious tools, but to understand **how they work**, how to reverse them, and how to stop 
them.

---

## 🔧 What It Does

- AES-256-CBC file encryption using OpenSSL's `EVP_CIPHER_CTX`
- Automatic PKCS#7 padding
- SHA-256 hashing of encrypted files
- Stealth mode to hide output
- Random IV generation and prepending
- Handles any file size (resolves 16-byte corruption issue in original implementation)

---

## 🐛 What I Fixed (From My First Version)

Originally, I used `AES_encrypt()` and `AES_decrypt()` which only work with exact 16-byte blocks and no padding. This 
caused corrupted output when encrypting regular files.

In this version:
- I switched to `EVP_EncryptInit_ex()` and `EVP_DecryptInit_ex()`
- Introduced PKCS#7 padding
- Cleaned up error handling and added SHA verification
- Simulated more malware-like behavior (stealth + IV randomization)

---

## 💡 Learning Goals

This project was my attempt to:
- Understand the internals of symmetric file encryption
- Build intuition on how ransomware works at the code level
- Prepare for reverse engineering using Ghidra
- Expand my cybersecurity portfolio alongside Pwn College and future CTFs

---

## 🧪 Try It

```bash
echo "TOP SECRET INTEL — DO NOT SHARE" > input.txt

# Encrypt
./securefileencrypt input.txt encrypted.bin

# Decrypt
cat decrypted_output.txt

# Stealth mode
./securefileencrypt input.txt encrypted.bin --stealth

