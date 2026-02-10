from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def encrypt_data(public_key_pem, data):
    public_key = serialization.load_pem_public_key(public_key_pem)

    encrypted = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def decrypt_data(private_key_pem, encrypted_data):
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )

    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()


if __name__ == "__main__":
    private_key, public_key = generate_keys()
    message = "Sensitive patient diagnosis"

    encrypted = encrypt_data(public_key, message)
    decrypted = decrypt_data(private_key, encrypted)

    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)
