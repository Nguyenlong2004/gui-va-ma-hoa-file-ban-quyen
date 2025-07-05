import socket
import os
import json
import base64
from Crypto.Cipher import DES3, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes

def log(msg):
    print(f"[Sender] ✅ {msg}")

# 1. Kết nối tới Receiver
s = socket.socket()
s.connect(('localhost', 12345))
s.send(b"Hello!")
response = s.recv(1024).decode()
if response != "Ready!":
    print("[Sender] ❌ Receiver không sẵn sàng.")
    s.close()
    exit()
log("Receiver đã sẵn sàng.")

# 2. Tạo và ký metadata
metadata = {
    "filename": "Song_1.mp3",
    "copyright": "ABC Music 2025"
}
meta_str = json.dumps(metadata)
log("Metadata đã tạo.")

private_key = RSA.import_key(open("private.pem").read())
hash_meta = SHA512.new(meta_str.encode())
signature = pkcs1_15.new(private_key).sign(hash_meta)
log("Metadata đã ký.")

# 3. Tạo khóa phiên
session_key_3des = DES3.adjust_key_parity(get_random_bytes(24))  # Triple DES key
session_key_des = get_random_bytes(8)  # DES key
log("Đã tạo khóa phiên.")

# 4. Mã hóa khóa phiên với RSA
receiver_pub = RSA.import_key(open("receiver_pub.pem").read())
cipher_rsa = PKCS1_OAEP.new(receiver_pub)
enc_session_key = cipher_rsa.encrypt(session_key_3des + session_key_des)
s.send(enc_session_key)
log("Đã gửi khóa phiên (mã hóa RSA).")

# 5. Đọc và mã hóa file
file_path = os.path.join(os.path.dirname(__file__), "sound", "Song_1.mp3")
with open(file_path, "rb") as f:
    song_data = f.read()
log(f"Đã đọc file nhạc: {file_path}")

iv = get_random_bytes(8)
cipher3des = DES3.new(session_key_3des, DES3.MODE_CBC, iv)
pad_len = 8 - (len(song_data) % 8)
song_data += bytes([pad_len]) * pad_len
ciphertext = cipher3des.encrypt(song_data)
log("Đã mã hóa file bằng Triple DES.")

# 6. Mã hóa metadata bằng DES
cipher_des = DES.new(session_key_des, DES.MODE_ECB)
meta_bytes = meta_str.encode()
pad_len = 8 - (len(meta_bytes) % 8)
meta_bytes += bytes([pad_len]) * pad_len
meta_enc = cipher_des.encrypt(meta_bytes)
log("Đã mã hóa metadata bằng DES.")

# 7. Tính hash toàn vẹn
hash_obj = SHA512.new(iv + ciphertext)

# 8. Tạo gói tin và gửi
packet = {
    "iv": base64.b64encode(iv).decode(),
    "cipher": base64.b64encode(ciphertext).decode(),
    "meta": base64.b64encode(meta_enc).decode(),
    "hash": hash_obj.hexdigest(),
    "sig": base64.b64encode(signature).decode()
}

packet_bytes = json.dumps(packet).encode()
s.sendall(len(packet_bytes).to_bytes(4, byteorder='big'))
s.sendall(packet_bytes)
log("Đã gửi gói tin.")

# 9. Nhận phản hồi
try:
    result = s.recv(1024).decode()
    if result == "ACK":
        log("Người nhận đã xác nhận (ACK). Thành công.")
    else:
        print("[Sender] ❌ Gửi thất bại. Nhận phản hồi:", result)
except Exception as e:
    print(f"[Sender] ❌ Lỗi nhận phản hồi: {e}")

s.close()
