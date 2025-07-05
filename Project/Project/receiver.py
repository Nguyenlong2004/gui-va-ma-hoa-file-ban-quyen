import socket
import os
import json
import base64
from Crypto.Cipher import DES3, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15

def log(msg):
    print(f"[Receiver] {msg}")

# 1. Chờ kết nối và handshake
s = socket.socket()
s.bind(('localhost', 12345))
s.listen(1)
log("Đang chờ kết nối...")
conn, addr = s.accept()
log(f"Kết nối từ: {addr}")

msg = conn.recv(1024).decode()
log(f"Nhận được: {msg}")
if msg != "Hello!":
    log("Sai tín hiệu đầu vào.")
    conn.close()
    exit()
conn.send(b"Ready!")
log("Đã gửi: Ready!")

# 2. Nhận và giải mã khóa phiên
enc_session_key = conn.recv(1024)
log("Đã nhận khóa phiên (mã hóa).")

private_key = RSA.import_key(open("private_receiver.pem").read())
cipher_rsa = PKCS1_OAEP.new(private_key)
try:
    full_key = cipher_rsa.decrypt(enc_session_key)
    session_key_3des = full_key[:24]
    session_key_des = full_key[24:]
    log("Giải mã session key thành công.")
except ValueError:
    log("Giải mã session key thất bại.")
    conn.close()
    exit()

# 3. Nhận gói tin
log("Đang nhận độ dài gói tin...")
length_bytes = conn.recv(4)
total_length = int.from_bytes(length_bytes, byteorder='big')
log(f"Đang nhận {total_length} byte gói tin...")

packet_data = b''
while len(packet_data) < total_length:
    chunk = conn.recv(4096)
    if not chunk:
        break
    packet_data += chunk
log("Đã nhận đủ gói tin.")

# 4. Phân tích gói tin
try:
    packet = json.loads(packet_data.decode())
except Exception as e:
    log(f"Lỗi khi giải mã JSON gói tin: {e}")
    conn.send(b"NACK")
    conn.close()
    exit()

iv = base64.b64decode(packet["iv"])
ciphertext = base64.b64decode(packet["cipher"])
meta_enc = base64.b64decode(packet["meta"])
sig = base64.b64decode(packet["sig"])
hash_recv = packet["hash"]

# 5. Kiểm tra hash
hash_obj = SHA512.new(iv + ciphertext)
log(f"Hash tính được: {hash_obj.hexdigest()}")
log(f"Hash nhận được: {hash_recv}")
if hash_obj.hexdigest() != hash_recv:
    log("Sai hash, từ chối gói tin.")
    conn.send(b"NACK")
    conn.close()
    exit()
log("Hash hợp lệ.")

# 6. Giải mã metadata bằng DES
cipher_des = DES.new(session_key_des, DES.MODE_ECB)
meta_padded = cipher_des.decrypt(meta_enc)
pad_len = meta_padded[-1]
meta_json = meta_padded[:-pad_len].decode()

try:
    metadata = json.loads(meta_json)
    log(f"Metadata giải mã: {metadata}")
except:
    log("Lỗi khi phân tích metadata.")
    conn.send(b"NACK")
    conn.close()
    exit()

# 7. Xác thực chữ ký
pub_key_sender = RSA.import_key(open("sender_pub.pem").read())
hash_meta = SHA512.new(meta_json.encode())
try:
    pkcs1_15.new(pub_key_sender).verify(hash_meta, sig)
    log("Chữ ký hợp lệ.")
except (ValueError, TypeError):
    log("Chữ ký không hợp lệ.")
    conn.send(b"NACK")
    conn.close()
    exit()

# 8. Giải mã file nhạc
cipher3des = DES3.new(session_key_3des, DES3.MODE_CBC, iv)
song_padded = cipher3des.decrypt(ciphertext)
pad_len = song_padded[-1]
song_data = song_padded[:-pad_len]

# 9. Lưu file
save_path = os.path.join(os.path.dirname(__file__), "received_" + metadata['filename'])
with open(save_path, "wb") as f:
    f.write(song_data)
log(f"File đã lưu tại: {save_path}")

conn.send(b"ACK")
conn.close()
log("Đã gửi ACK. Kết thúc kết nối.")
