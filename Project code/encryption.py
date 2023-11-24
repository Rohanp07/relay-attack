from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_key_pair():
    """Generate an RSA key pair and return private and public keys."""
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return private_key.export_key(), public_key.export_key()

def encrypt_message(message, public_key):
    """Encrypt a message using a public key."""
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher_rsa.encrypt(message)
    return encrypted_message

def decrypt_message(encrypted_message, private_key):
    """Decrypt an encrypted message using a private key."""
    private_key_obj = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key_obj)
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    return decrypted_message
