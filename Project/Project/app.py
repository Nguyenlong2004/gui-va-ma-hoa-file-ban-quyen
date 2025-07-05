from flask import Flask, render_template, request, send_file, jsonify
from Crypto.Cipher import DES3, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json
import base64
import os

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def load_key(filename):
    path = os.path.join(BASE_DIR, filename)
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

PRIVATE_KEY = load_key("private.pem")
RECEIVER_PUB_KEY = load_key("receiver_pub.pem")
SENDER_PUB_KEY = load_key("sender_pub.pem")
RECEIVER_PRIVATE_KEY = load_key("private_receiver.pem")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    uploaded_file = request.files['file']
    metadata = json.loads(request.form['metadata'])
    mode = request.form.get("mode", "encrypt-sign")

    file_data = uploaded_file.read()

    # Sinh khóa
    des3_key = DES3.adjust_key_parity(get_random_bytes(24))
    des_key = get_random_bytes(8)

    des3_cipher = DES3.new(des3_key, DES3.MODE_EAX)
    file_ciphertext, file_tag = des3_cipher.encrypt_and_digest(file_data)

    metadata_bytes = json.dumps(metadata).encode()
    des_cipher = DES.new(des_key, DES.MODE_EAX)
    meta_ciphertext, meta_tag = des_cipher.encrypt_and_digest(metadata_bytes)

    packet = {
        'mode': mode,
        'file_ciphertext': base64.b64encode(file_ciphertext).decode(),
        'file_nonce': base64.b64encode(des3_cipher.nonce).decode(),
        'file_tag': base64.b64encode(file_tag).decode(),
        'meta_ciphertext': base64.b64encode(meta_ciphertext).decode(),
        'meta_nonce': base64.b64encode(des_cipher.nonce).decode(),
        'meta_tag': base64.b64encode(meta_tag).decode(),
    }

    if mode == "encrypt-sign":
        h = SHA256.new(metadata_bytes)
        signature = pkcs1_15.new(PRIVATE_KEY).sign(h)
        packet['signature'] = base64.b64encode(signature).decode()

    session = des3_key + des_key
    rsa_cipher = PKCS1_OAEP.new(RECEIVER_PUB_KEY)
    enc_session_key = rsa_cipher.encrypt(session)
    packet['enc_session_key'] = base64.b64encode(enc_session_key).decode()

    out_file = os.path.join(BASE_DIR, "encrypted_packet.json")
    with open(out_file, "w") as f:
        json.dump(packet, f)

    return send_file(out_file, as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    enc_file = request.files['enc_file']
    packet = json.load(enc_file)

    enc_session_key = base64.b64decode(packet['enc_session_key'])
    rsa_cipher = PKCS1_OAEP.new(RECEIVER_PRIVATE_KEY)
    session = rsa_cipher.decrypt(enc_session_key)
    des3_key, des_key = session[:24], session[24:]

    des_cipher = DES.new(des_key, DES.MODE_EAX, nonce=base64.b64decode(packet['meta_nonce']))
    metadata_bytes = des_cipher.decrypt_and_verify(
        base64.b64decode(packet['meta_ciphertext']),
        base64.b64decode(packet['meta_tag'])
    )

    metadata = json.loads(metadata_bytes)

    if packet.get("mode") == "encrypt-sign":
        h = SHA256.new(metadata_bytes)
        signature = base64.b64decode(packet['signature'])
        try:
            pkcs1_15.new(SENDER_PUB_KEY).verify(h, signature)
        except (ValueError, TypeError):
            return "❌ Chữ ký không hợp lệ!", 400

    des3_cipher = DES3.new(des3_key, DES3.MODE_EAX, nonce=base64.b64decode(packet['file_nonce']))
    file_data = des3_cipher.decrypt_and_verify(
        base64.b64decode(packet['file_ciphertext']),
        base64.b64decode(packet['file_tag'])
    )

    filename = metadata.get('filename', 'decrypted_file.bin')
    output_path = os.path.join(BASE_DIR, filename)
    with open(output_path, "wb") as f:
        f.write(file_data)

    # Ghi lại metadata để hiển thị
    with open(os.path.join(BASE_DIR, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=4)

    return send_file(output_path, as_attachment=True)

@app.route('/view-metadata')
def view_metadata():
    path = os.path.join(BASE_DIR, "metadata.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return f"<pre>{f.read()}</pre>"
    return "📭 Chưa có metadata nào được giải mã!"

@app.route('/view-packet')
def view_packet():
    path = os.path.join(BASE_DIR, "encrypted_packet.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return f"<pre>{f.read()}</pre>"
    return "📭 Chưa có gói mã hóa nào được tạo!"

if __name__ == '__main__':
    app.run(debug=True)
