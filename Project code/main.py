import random
from encryption import generate_key_pair
from car_key_authentication import car_generate_challenge, car_key_respond_to_challenge, car_verify_challenge_response
from central_system import register_with_security_system

def authenticate_car_key(car_private_key, car_key_private_key, car_key_public_key):
    """Function to simulate the car key authentication process."""
    print("\nCar key trying to start the car...")

    challenge = car_generate_challenge()

    # Introduce only a 1% chance to use a wrong key (simulating a very rare unauthorized access attempt)
    if random.uniform(0, 1) < 0.01:  
        wrong_private_key, _ = generate_key_pair()  # Generating wrong keys for the car key
        signature = car_key_respond_to_challenge(challenge, wrong_private_key)
    else:
        signature = car_key_respond_to_challenge(challenge, car_key_private_key)

    is_valid = car_verify_challenge_response(challenge, signature, car_key_public_key)

    if is_valid:
        print("Car key authenticated successfully! Car starts.\n")
        return True
    else:
        print("Car key authentication failed! Car doesn't start.\n")
        return False

def main():
    print("Initializing car and car key with key pairs...")
    car_private_key, car_public_key = generate_key_pair()
    car_key_private_key, car_key_public_key = generate_key_pair()

    if authenticate_car_key(car_private_key, car_key_private_key, car_key_public_key):
        print("Generating a new key pair for the car...")
        car_private_key, car_public_key = generate_key_pair()

        print("Registering car's new public key with the central security system...")
        car_id = "CAR_1234"
        response = register_with_security_system(car_id, car_public_key)
        print(response)

if __name__ == "__main__":
    main()
