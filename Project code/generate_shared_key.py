from Crypto.Random import get_random_bytes


# 使用get_random_bytes生成随机密钥
CARKEY_AS_SHARED_KEY = get_random_bytes(32)
AS_TGS_SHARED_KEY = get_random_bytes(32)
TGS_CAR_SHARED_KEY = get_random_bytes(32)

# 将生成的密钥保存到PEM文件
file_path1 = "carkey_as_shared_key.pem"
with open(file_path1, "wb") as key_file:
    key_file.write(CARKEY_AS_SHARED_KEY)

file_path2 = "as_tgs_shared_key.pem"
with open(file_path2, "wb") as key_file:
    key_file.write(AS_TGS_SHARED_KEY)

file_path3 = "tgs_car_shared_key.pem"
with open(file_path3, "wb") as key_file:
    key_file.write(TGS_CAR_SHARED_KEY)

# 从文件中读取密钥
# with open(file_path, "rb") as key_file:
#     loaded_key = key_file.read()
