import base64

from flask import Flask, request, jsonify
import pickle
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

# 定义已注册设备ID，只允许已注册的设备访问
registered_device_list = ['CK993Y8ER5']

def encrypt(key: bytes, data: Any) -> bytes:
    """Encrypts the given data using AES."""
    # Convert data to bytes
    data_bytes = pickle.dumps(data)

    # Assign the nonce & the length of the MAC tag
    nonce = get_random_bytes(AES.block_size)

    # Initialize AES cipher in GCM mode
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=AES.block_size)
    # cipher.update(b"")

    # Encrypt the data
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)

    encrypted_data = {
        'nonce': cipher.nonce,
        'ciphertext': ciphertext,
        'tag': tag
    }

    # Return encrypted data with nonce and tag

    return pickle.dumps(encrypted_data)


def decrypt(key: bytes, data: bytes) -> Any:
    """Decrypts the given message using AES."""
    encrypted_data = pickle.loads(data)

    # Extract components
    nonce = encrypted_data['nonce']
    ciphertext = encrypted_data['ciphertext']
    tag = encrypted_data['tag']

    # Initialize AES cipher in GCM mode
    # print(f"nonce is {nonce}")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=AES.block_size)

    # Decrypt the data
    try:
        decrypted_data = pickle.loads(cipher.decrypt_and_verify(ciphertext, tag))

        return decrypted_data

    except ValueError:
        # Return None for not authentic message
        return None

@dataclass(frozen=True)
class Ticket:
    """A ticket that acts as both a ticket-granting ticket (TGT) and a service ticket."""

    username: str
    session_key: bytes
    validity: float = field(init=False, default_factory=lambda: time.time() + 3600)


@dataclass(frozen=True)
class Authenticator:
    """An authenticator used by the client to confirm their identity with the various servers."""

    username: str
    timestamp: float = field(init=False, default_factory=time.time)


@dataclass(frozen=True)
class CarResponse:
    """A response to a file request that contains the file's data and a timestamp to confirm the file server's identity."""

    message: str
    timestamp: float

# 定义路由和处理函数
@app.route('/carkey_request_ticket', methods=['POST'])
def carkey_request_ticket():
    # get data from request
    req_data = request.get_json()

    with open("tgs_car_shared_key.pem", "rb") as key_file:
        TGS_CAR_SHARED_KEY = key_file.read()

    with open("as_tgs_shared_key.pem", "rb") as key_file:
        AS_TGS_SHARED_KEY = key_file.read()

    if req_data:
        encrypted_as_to_carKey_tgt = base64.b64decode(req_data.get('message3').encode('utf-8'))
        encrypted_carKey_TGS_authenticator = base64.b64decode(req_data.get('message4').encode('utf-8'))

        decrypted_as_to_carKey_tgt = decrypt(AS_TGS_SHARED_KEY, encrypted_as_to_carKey_tgt)


        decrypted_carkey_TGS_session_key = decrypted_as_to_carKey_tgt.session_key

        decrypted_carKey_TGS_authenticator = decrypt(decrypted_carkey_TGS_session_key,
                                                     encrypted_carKey_TGS_authenticator)

        # Authenticate both device ID & timestamp
        if decrypted_as_to_carKey_tgt.username != decrypted_carKey_TGS_authenticator.username:
            print(f"Device authentication fail (Device not matched)")

            return jsonify({'error': 'Device not matched'})

        if decrypted_as_to_carKey_tgt.validity > time.time() + 3540:
            print(f"Granting ticket expired")

            return jsonify({'error': 'Granting ticket expired'})

        # Message 5
        carKey_car_session_key = get_random_bytes(16)
        encrypted_carKey_car_session_key = encrypt(decrypted_carkey_TGS_session_key, carKey_car_session_key)
        encrypted_carKey_car_session_key_base64 = base64.b64encode(encrypted_carKey_car_session_key).decode('utf-8')

        # Message 6
        tgs_ticket = Ticket(decrypted_as_to_carKey_tgt.username, carKey_car_session_key)
        encrypted_tgs_ticket = encrypt(TGS_CAR_SHARED_KEY, tgs_ticket)
        encrypted_tgs_ticket_base64 = base64.b64encode(encrypted_tgs_ticket).decode('utf-8')

        response = {'message5': encrypted_carKey_car_session_key_base64,
                    'message6': encrypted_tgs_ticket_base64}

        return jsonify(response), 200
    else:
        return jsonify({'error': 'No data received'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5001)  # 启动应用，在 http://127.0.0.1:5001/
