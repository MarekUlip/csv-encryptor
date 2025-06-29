from flask import Flask, request, jsonify, send_file, send_from_directory
from werkzeug.utils import secure_filename
from flask_cors import CORS
from io import BytesIO
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import os

app = Flask(__name__, static_folder="../frontend", static_url_path="/")
CORS(app)  # Allow frontend to access backend API

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, "decrypt.html")

@app.route('/api/decrypt', methods=['POST'])
def decrypt_csv():
    file = request.files.get('file')
    password = request.form.get('password')

    if not file or not password:
        return jsonify({'error': 'File and password are required'}), 400

    content = file.read()
    salt = content[:16]
    iv = content[16:28]
    encrypted_data = content[28:]

    try:
        key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        # Split ciphertext and tag
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]

        # Decrypt and verify
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)

        csv_stream = BytesIO(decrypted)
        return send_file(csv_stream, mimetype='text/csv', as_attachment=True, download_name='decrypted.csv')
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400
