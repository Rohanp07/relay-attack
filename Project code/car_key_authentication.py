from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

def car_generate_challenge():
    """Generate a random challenge for car-key authentication."""
    return get_random_bytes(32)  # random 32 bytes

def car_key_respond_to_challenge(challenge, car_key_private_key):
    """Car key's response to the car's challenge using its private key."""
    h = SHA256.new(challenge)
    signature = pkcs1_15.new(RSA.import_key(car_key_private_key)).sign(h)
    return signature

def car_verify_challenge_response(challenge, signature, car_key_public_key):
    """Car verifies the challenge response to determine if the car key is authentic."""
    h = SHA256.new(challenge)
    try:
        pkcs1_15.new(RSA.import_key(car_key_public_key)).verify(h, signature)
        return True  # Signature is valid
    except (ValueError, TypeError):
        return False  # Signature is invalid

