from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_data(key, data):
    cipher = Fernet(key)
    return cipher.encrypt(data.encode())

def decrypt_data(key, encrypted_data):
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data).decode()


if __name__ == "__main__":
    key = generate_key()
    data = "Patient medical history"

    encrypted = encrypt_data(key, data)
    decrypted = decrypt_data(key, encrypted)

    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)
