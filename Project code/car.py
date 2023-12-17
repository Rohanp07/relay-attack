import base64
import json

from flask import Flask, request, jsonify
import socket
import threading
import pickle
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

# 定义白名单，包含允许连接的客户端 IP 地址
whitelist = ['127.0.0.1', '10.0.0.109', '99.243.177.47']

def handle_client(client_socket, client_address):
    if client_address[0] not in whitelist:
        print(f"Connection from {client_address} rejected (not in whitelist).")
        client_socket.close()
        return

    print(f"Connected by {client_address}")
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        print(f'Received data from {client_address}: {data.decode()}')

        received_json = data.decode('utf-8')
        received_json_data = json.loads(received_json)

        with open("tgs_car_shared_key.pem", "rb") as key_file:
            TGS_CAR_SHARED_KEY = key_file.read()

        if received_json_data:
            encrypted_tgs_ticket = base64.b64decode(received_json_data.get('message6').encode('utf-8'))
            encrypted_to_car_authenticator = base64.b64decode(received_json_data.get('message7').encode('utf-8'))

            decrypted_tgs_ticket = decrypt(TGS_CAR_SHARED_KEY, encrypted_tgs_ticket)

            carKey_car_session_key = decrypted_tgs_ticket.session_key

            decrypted_to_car_authenticator = decrypt(carKey_car_session_key, encrypted_to_car_authenticator)

            # Authenticate device ID & timestamp
            if decrypted_tgs_ticket.username != decrypted_to_car_authenticator.username:
                print(f"Device authentication fail (Device not matched)")

                return jsonify({'error': 'Device not matched'})

            if decrypted_tgs_ticket.validity - time.time() < 3540:
                print(f"Service Ticket expired")

                return jsonify({'error': 'Service Ticket expired'})

            # Message 8
            message = 'Door has been unlocked'
            car_response = CarResponse(message, time.time())
            encrypted_car_response = encrypt(carKey_car_session_key, car_response)

            encrypted_car_response_base64 = base64.b64encode(encrypted_car_response).decode('utf-8')

            response = {'message8': encrypted_car_response_base64}

            json_response = json.dumps(response)

            data_to_send = json_response.encode('utf-8')

        else:
            data_to_send = jsonify({'error': 'No data received'})

        # 响应客户端，发送相同的数据
        client_socket.sendall(data_to_send)
        print(f"Sent data to {client_address}: {data_to_send.decode()}")

    client_socket.close()

def start_server():
    # server_address = ('127.0.0.1', 8888)
    server_address = ('0.0.0.0', 8888)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(server_address)
        server_socket.listen(5)
        print("Waiting for connection...")

        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()

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
@app.route('/carkey_request_car', methods=['POST'])
def carkey_request_car():
    # get data from request
    req_data = request.get_json()

    with open("tgs_car_shared_key.pem", "rb") as key_file:
        TGS_CAR_SHARED_KEY = key_file.read()

    if req_data:
        encrypted_tgs_ticket = base64.b64decode(req_data.get('message6').encode('utf-8'))
        encrypted_to_car_authenticator = base64.b64decode(req_data.get('message7').encode('utf-8'))

        decrypted_tgs_ticket = decrypt(TGS_CAR_SHARED_KEY, encrypted_tgs_ticket)

        carKey_car_session_key = decrypted_tgs_ticket.session_key

        decrypted_to_car_authenticator = decrypt(carKey_car_session_key, encrypted_to_car_authenticator)

        # Authenticate device ID & timestamp
        if decrypted_tgs_ticket.username != decrypted_to_car_authenticator.username:
            print(f"Device authentication fail (Device not matched)")

            return jsonify({'error': 'Device not matched'})

        if decrypted_tgs_ticket.validity - time.time() < 3540:
            print(f"validity: {decrypted_tgs_ticket.validity}, now: {time.time()}")
            print(f"Service Ticket expired")

            return jsonify({'error': 'Service Ticket expired'})

        # Message 8
        message = 'Door has been unlocked'
        car_response = CarResponse(message, time.time())
        encrypted_car_response = encrypt(carKey_car_session_key, car_response)

        encrypted_car_response_base64 = base64.b64encode(encrypted_car_response).decode('utf-8')

        response = {'message8': encrypted_car_response_base64}

        return jsonify(response), 200
    else:
        return jsonify({'error': 'No data received'})

if __name__ == '__main__':
    # app.run(debug=True, port=5002)  # 启动应用，在 http://127.0.0.1:5002/
    start_server()
