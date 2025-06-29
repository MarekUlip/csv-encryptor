from flask import Flask, request, jsonify, send_file, send_from_directory
from werkzeug.utils import secure_filename
from flask_cors import CORS
from io import BytesIO
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import os
import pyzipper

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


@app.route('/api/decrypt_zip', methods=['POST'])
def decrypt_csv_zip():
    file = request.files.get('file')
    password = request.form.get('password')

    if not file or not password:
        return jsonify({'error': 'File and password are required'}), 400

    content = file.read()
    salt = content[:16]
    iv = content[16:28]
    encrypted_data = content[28:]

    try:
        #Hash module is very important without it it does not work
        key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]

        decrypted = cipher.decrypt_and_verify(ciphertext, tag)

        # Create ZIP in memory
        zip_buffer = BytesIO()
        with pyzipper.AESZipFile(zip_buffer, 'w', compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password.encode('utf-8'))
            zf.setencryption(pyzipper.WZ_AES, nbits=256)
            zf.writestr("decrypted.csv", decrypted)

        zip_buffer.seek(0)
        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='decrypted_csv.zip')

    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400


@app.route('/api/encrypt_text_zip', methods=['POST'])
def encrypt_text_zip():
    text = request.form.get('text')
    password = request.form.get('password')

    if not text or not password:
        return jsonify({'error': 'Text and password are required'}), 400

    content = text

    try:

        # Create ZIP in memory
        zip_buffer = BytesIO()
        with pyzipper.AESZipFile(zip_buffer, 'w', compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password.encode('utf-8'))
            zf.setencryption(pyzipper.WZ_AES, nbits=256)
            zf.writestr("encrypted.txt", content)

        zip_buffer.seek(0)
        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='encrypted.zip')

    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 400