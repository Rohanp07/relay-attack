import base64
import json
import datetime

import requests
import socket
import pickle
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class CarKey:
    def __init__(self, deviceID, shared_key):

        self.deviceID = deviceID
        self.shared_key = shared_key

    def https_send(self, url, data_to_send):
            try:
                response = requests.post(url, json=data_to_send)
                if response.status_code == 200:
                    print('HTTPS request success')
                    print('Received json:', response.json())
                    return response.json()
                else:
                    print('HTTPS request fail', response.status_code)
                    return None

            except requests.RequestException as e:
                print('HTTPS error:', e)
                return None

    def simulate_bluetooth_communication(self, data):
        # simulate bluetooth communication
        try:
            # create socket object
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bluetooth_socket:
                # address & port of bluetooth device
                # remote_address = '127.0.0.1'
                remote_address = '99.79.51.184'
                remote_port = 8888

                # connect with bluetooth device
                bluetooth_socket.connect((remote_address, remote_port))

                json_data = json.dumps(data)  # 将 JSON 对象转换为字符串
                json_data_bytes = json_data.encode('utf-8')  # 将字符串编码为字节流

                # send data
                bluetooth_socket.sendall(json_data_bytes)

                # receive response
                received_data = bluetooth_socket.recv(1024)
                received_json = received_data.decode('utf-8')
                json_data = json.loads(received_json)
                print('Received bluetooth data:', received_data.decode())

                return json_data
        except socket.error as e:
            print('Bluetooth communication error:', e)
            return None

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

def main():
    with open("carkey_as_shared_key.pem", "rb") as key_file:
        CARKEY_AS_SHARED_KEY = key_file.read()

    car_key = CarKey("CK993Y8ER5", CARKEY_AS_SHARED_KEY)

    application_start_time = datetime.datetime.now()

    authenticator_to_as = Authenticator(car_key.deviceID)

    encryption_message_1_start_time = datetime.datetime.now()
    encrypted_authenticator = encrypt(CARKEY_AS_SHARED_KEY, authenticator_to_as)
    encryption_message_1_end_time = datetime.datetime.now()

    encryption_message_1_elapsed_time = encryption_message_1_end_time - encryption_message_1_start_time

    print("Encrypt message to AS Elapsed time:", encryption_message_1_elapsed_time.total_seconds() * 1000)

    encrypted_authenticator_base64 = base64.b64encode(encrypted_authenticator).decode('utf-8')

    data_to_as = {'authenticator': encrypted_authenticator_base64}

    # http communication, send request to AS
    communication_with_as_start_time = datetime.datetime.now()
    # as_response = car_key.https_send("http://127.0.0.1:5000/carkey_send_request", data_to_as)
    as_response = car_key.https_send("http://99.79.51.184:5000/carkey_send_request", data_to_as)
    communication_with_as_end_time = datetime.datetime.now()

    communication_with_as_elapsed_time = communication_with_as_end_time - communication_with_as_start_time

    print("Communicate with AS Elapsed time:", communication_with_as_elapsed_time.total_seconds() * 1000)



    encrypted_carKey_TGS_session_key = base64.b64decode(as_response.get('message2').encode('utf-8'))
    encrypted_as_to_carKey_tgt = base64.b64decode(as_response.get('message3').encode('utf-8'))

    # encrypted_as_to_carKey_tgt_base64 = base64.b64decode(encrypted_as_to_carKey_tgt).decode('utf-8')

    decrypt_message_from_as_start_time = datetime.datetime.now()
    decrypted_carKey_TGS_session_key = decrypt(CARKEY_AS_SHARED_KEY, encrypted_carKey_TGS_session_key)
    decrypt_message_from_as_end_time = datetime.datetime.now()

    decrypt_message_from_as_elapsed_time = decrypt_message_from_as_end_time - decrypt_message_from_as_start_time

    print("Decrypt message from AS Elapsed time:", decrypt_message_from_as_elapsed_time.total_seconds() * 1000)

    # Message 4
    authenticator_to_tgs = Authenticator(car_key.deviceID)

    encryption_message_4_start_time = datetime.datetime.now()
    encrypted_carKey_TGS_authenticator = encrypt(decrypted_carKey_TGS_session_key, authenticator_to_tgs)
    encryption_message_4_end_time = datetime.datetime.now()

    encryption_message_4_elapsed_time = encryption_message_4_end_time - encryption_message_4_start_time

    print("Encrypt message to TGS Elapsed time:", encryption_message_4_elapsed_time.total_seconds() * 1000)

    encrypted_carKey_TGS_authenticator_base64 = base64.b64encode(encrypted_carKey_TGS_authenticator).decode('utf-8')

    data_to_tgs = {'message3': as_response.get('message3'),
                   'message4': encrypted_carKey_TGS_authenticator_base64}

    # http communication, send request to TGS
    communication_with_tgs_start_time = datetime.datetime.now()
    # tgs_response = car_key.https_send("http://127.0.0.1:5001/carkey_request_ticket", data_to_tgs)
    tgs_response = car_key.https_send("http://99.79.51.184:5001/carkey_request_ticket", data_to_tgs)
    communication_with_tgs_end_time = datetime.datetime.now()

    communication_with_tgs_elapsed_time = communication_with_tgs_end_time - communication_with_tgs_start_time

    print("Communicate with TGS Elapsed time:", communication_with_tgs_elapsed_time.total_seconds() * 1000)


    encrypted_carKey_car_session_key = base64.b64decode(tgs_response.get('message5').encode('utf-8'))

    encrypted_tgs_ticket = base64.b64decode(tgs_response.get('message6').encode('utf-8'))
    # encrypted_tgs_ticket_base64 = base64.b64encode(encrypted_tgs_ticket).decode('utf-8')

    decrypt_message_from_tgs_start_time = datetime.datetime.now()
    decrypted_carKey_car_session_key = decrypt(decrypted_carKey_TGS_session_key, encrypted_carKey_car_session_key)
    decrypt_message_from_tgs_end_time = datetime.datetime.now()

    decrypt_message_from_tgs_elapsed_time = decrypt_message_from_tgs_end_time - decrypt_message_from_tgs_start_time

    print("Decrypt message from TGS Elapsed time:", decrypt_message_from_tgs_elapsed_time.total_seconds() * 1000)

    # Message 7
    authenticator_to_car = Authenticator(car_key.deviceID)

    encryption_message_7_start_time = datetime.datetime.now()
    encrypted_to_car_authenticator = encrypt(decrypted_carKey_car_session_key, authenticator_to_car)
    encryption_message_7_end_time = datetime.datetime.now()

    encryption_message_7_elapsed_time = encryption_message_7_end_time - encryption_message_7_start_time

    print("Encrypt message to Car Elapsed time:", encryption_message_7_elapsed_time.total_seconds() * 1000)

    encrypted_to_car_authenticator_base64 = base64.b64encode(encrypted_to_car_authenticator).decode('utf-8')

    data_to_car = {'message6': tgs_response.get('message6'),
                   'message7': encrypted_to_car_authenticator_base64}

    # http communication, send request to Car
    # car_response = car_key.https_send("http://127.0.0.1:5002/carkey_request_car", data_to_car)
    #
    # car_response_content = base64.b64decode(car_response.get('message8').encode('utf-8'))
    #
    # decrypted_car_response = decrypt(decrypted_carKey_car_session_key, car_response_content)
    #
    # car_message = decrypted_car_response.message
    #
    # print('Response from car:', car_message)

    # bluetooth communication, send request to Car
    communication_with_car_start_time = datetime.datetime.now()
    car_response_bt = car_key.simulate_bluetooth_communication(data_to_car)
    communication_with_car_end_time = datetime.datetime.now()

    communication_with_car_elapsed_time = communication_with_car_end_time - communication_with_car_start_time

    print("Communicate with Car Elapsed time:", communication_with_car_elapsed_time.total_seconds() * 1000)

    car_response_bt_content = base64.b64decode(car_response_bt.get('message8').encode('utf-8'))

    decrypted_car_response_bt = decrypt(decrypted_carKey_car_session_key, car_response_bt_content)

    car_message_bt = decrypted_car_response_bt.message

    print('Response from car Bluetooth:', car_message_bt)

    application_end_time = datetime.datetime.now()

    application_elapsed_time = application_end_time - application_start_time

    print("Application Elapsed time:", application_elapsed_time.total_seconds() * 1000)

if __name__ == "__main__":
    main()