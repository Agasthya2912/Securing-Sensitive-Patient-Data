import hashlib
import os

def hash_patient_data(patient_data: str):
    """
    Hash sensitive patient data using salted SHA-256.
    Returns salt and hash for secure storage.
    """

    # Generate random salt (16 bytes)
    salt = os.urandom(16)

    # Combine salt with patient data
    salted_data = salt + patient_data.encode('utf-8')

    # Generate SHA-256 hash
    hash_object = hashlib.sha256(salted_data)
    hashed_data = hash_object.hexdigest()

    return salt.hex(), hashed_data


def verify_patient_data(input_data, stored_salt, stored_hash):
    """
    Verify patient data by re-hashing with stored salt.
    """
    salt = bytes.fromhex(stored_salt)
    hashed_input = hashlib.sha256(
        salt + input_data.encode('utf-8')
    ).hexdigest()

    return hashed_input == stored_hash


if __name__ == "__main__":
    patient_record = "Name: John Doe | DOB: 01-01-1990 | ID: 123456"

    salt, hashed = hash_patient_data(patient_record)
    print("Salt:", salt)
    print("Hash:", hashed)

    print("Verification:",
          verify_patient_data(patient_record, salt, hashed))
