from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_text(text, key):
    # Pad the text to be a multiple of 16 bytes
    padded_text = text + (AES.block_size - len(text) % AES.block_size) * chr(AES.block_size - len(text) % AES.block_size)
    
    # Generate a random IV
    iv = get_random_bytes(AES.block_size)
    
    # Initialize AES cipher in CBC mode with the provided key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the padded text
    ciphertext = cipher.encrypt(padded_text.encode('utf-8'))
    
    # Combine IV and ciphertext and encode with base64
    encrypted_text = base64.b64encode(iv + ciphertext)
    
    return encrypted_text

def decrypt_text(encrypted_text, key):
    # Decode the base64 encoded text
    encrypted_text = base64.b64decode(encrypted_text)
    
    # Extract IV
    iv = encrypted_text[:AES.block_size]
    
    # Initialize AES cipher in CBC mode with the provided key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the ciphertext and remove padding
    decrypted_text = cipher.decrypt(encrypted_text[AES.block_size:]).rstrip(chr(AES.block_size).encode('utf-8'))
    
    return decrypted_text.decode('utf-8')

# Example usage:
key = b'thisisa16bytekey'  # 16 bytes key for AES-128
text = "Hello, this is a secret message!"

encrypted_text = encrypt_text(text, key)
print("Encrypted text:", encrypted_text)

decrypted_text = decrypt_text(encrypted_text, key)
print("Decrypted text:", decrypted_text)
