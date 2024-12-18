import hashlib, os

def hash_psd(psd: str) -> str:
    # Generate a random 16-byte salt
    salt = os.urandom(16)
    # Hash the password using PBKDF2-HMAC-SHA256
    hashed_psd = hashlib.pbkdf2_hmac('sha256', psd.encode(), salt, 100000)
    # Combine salt and hashed password as a single string
    return salt.hex() + hashed_psd.hex()

def verify_psd(stored_psd: str, provided_psd: str) -> bool:
    # Extract the salt from the stored password
    salt = bytes.fromhex(stored_psd[:32])
    # Extract the stored hash
    stored_hash = stored_psd[32:]
    # Recompute the hash for the provided password
    hashed_psd = hashlib.pbkdf2_hmac('sha256', provided_psd.encode(), salt, 100000)
    # Compare the recomputed hash with the stored hash
    return hashed_psd.hex() == stored_hash

if __name__ == "__main__":
    # Input password to hash and store
    psd_to_store = input("Enter a Password: ")
    stored_psd = hash_psd(psd_to_store)
    print(f"Stored Password: {stored_psd}")

    # Attempt to verify the password
    psd_attempt = 'clcoding'  # Replace with user input if needed
    is_valid = verify_psd(stored_psd, psd_attempt)
    print(f"Password is valid: {is_valid}")
