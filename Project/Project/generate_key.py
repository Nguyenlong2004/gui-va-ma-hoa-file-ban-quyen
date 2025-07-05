# generate_keys.py
from Crypto.PublicKey import RSA

# Tạo khóa RSA 1024-bit cho người gửi
key_sender = RSA.generate(1024)
with open("private.pem", "wb") as f:
    f.write(key_sender.export_key())
with open("sender_pub.pem", "wb") as f:
    f.write(key_sender.publickey().export_key())

# Tạo khóa RSA 1024-bit cho người nhận
key_receiver = RSA.generate(1024)
with open("private_receiver.pem", "wb") as f:
    f.write(key_receiver.export_key())
with open("receiver_pub.pem", "wb") as f:
    f.write(key_receiver.publickey().export_key())

print("\n✅ Đã tạo 4 file khóa:")
print("  - private.pem (khóa riêng người gửi)")
print("  - sender_pub.pem (khóa công khai người gửi)")
print("  - private_receiver.pem (khóa riêng người nhận)")
print("  - receiver_pub.pem (khóa công khai người nhận)")
