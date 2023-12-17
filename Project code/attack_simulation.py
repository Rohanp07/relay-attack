import requests
import json
import socket

def main():
    # 从 JSON 文件读取数据
    # with open("data_to_as.json", "r") as json_file1:
    #     loaded_data = json.load(json_file1)
    #     print(loaded_data)
    #     as_response = requests.post("http://99.79.51.184:5000/carkey_send_request", json=loaded_data)

    with open("data_to_tgs.json", "r") as json_file2:
        loaded_data = json.load(json_file2)
        print(loaded_data)
        tgs_response = requests.post("http://99.79.51.184:5001/carkey_request_ticket", json=loaded_data)

    # with open("data_to_car.json", "r") as json_file3:
    #     loaded_data = json.load(json_file3)
    #     print(loaded_data)
    #
    #     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bluetooth_socket:
    #         # address & port of bluetooth device
    #         # remote_address = '127.0.0.1'
    #         remote_address = '99.79.51.184'
    #         remote_port = 8888
    #
    #         # connect with bluetooth device
    #         bluetooth_socket.connect((remote_address, remote_port))
    #
    #         json_data = json.dumps(loaded_data)  # 将 JSON 对象转换为字符串
    #         json_data_bytes = json_data.encode('utf-8')  # 将字符串编码为字节流
    #
    #         # send data
    #         bluetooth_socket.sendall(json_data_bytes)
    #
    #         # receive response
    #         received_data = bluetooth_socket.recv(1024)
    #         received_json = received_data.decode('utf-8')
    #         json_data = json.loads(received_json)
    #         print('Received bluetooth data:', received_data.decode())

if __name__ == "__main__":

    main()