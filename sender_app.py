import socket
import os
import json
import time
from datetime import datetime
from base64 import b64encode, b64decode
import threading
from flask import Flask, render_template, request, jsonify
import math

from utils import (
    load_rsa_private_key, load_rsa_public_key,
    compute_sha512,
    encrypt_triple_des, rsa_encrypt,
    sign_data, send_data_packet, receive_data_packet,
    BUFFER_SIZE, RSA_KEY_SIZE, get_random_bytes, generate_rsa_keys
)

app = Flask(__name__, template_folder='templates')
app.config['UPLOAD_FOLDER'] = 'keys'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class SenderApp:
    def __init__(self):
        self.contract_filepath = None
        self.sender_private_key = None
        self.receiver_public_key = None
        self.socket_conn = None
        self.session_key = None
        self.session_iv = None
        self.is_connected = False
        self.activity_log = []  # Danh sách để lưu nhật ký hoạt động

    def generate_keys(self, output_dir):
        private_path = os.path.join(output_dir, "sender_private_key.pem")
        public_path = os.path.join(output_dir, "sender_public_key.pem")
        try:
            generate_rsa_keys(private_path, public_path)
            message = f"Đã tạo khóa tại: {output_dir}"
            self.activity_log.append(message)
            return True, message
        except Exception as e:
            message = f"Lỗi khi tạo khóa: {e}"
            self.activity_log.append(message)
            return False, message

    def load_sender_private_key(self, file_path):
        key = load_rsa_private_key(file_path)
        if key:
            self.sender_private_key = key
            message = f"Đã tải khóa riêng tư người gửi từ: {file_path}"
            self.activity_log.append(message)
            return True, message
        message = f"Không thể tải khóa riêng tư người gửi từ: {file_path}"
        self.activity_log.append(message)
        return False, message

    def load_receiver_public_key(self, file_path):
        key = load_rsa_public_key(file_path)
        if key:
            self.receiver_public_key = key
            message = f"Đã tải khóa công khai người nhận từ: {file_path}"
            self.activity_log.append(message)
            return True, message
        message = f"Không thể tải khóa công khai người nhận từ: {file_path}"
        self.activity_log.append(message)
        return False, message

    def connect_to_receiver(self, host, port):
        if self.is_connected:
            message = "Đã kết nối rồi."
            self.activity_log.append(message)
            return False, message
        if not self.sender_private_key or not self.receiver_public_key:
            message = "Thiếu khóa RSA để kết nối."
            self.activity_log.append(message)
            return False, message
        try:
            self.socket_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket_conn.connect((host, port))
            self.is_connected = True
            success, message = self._perform_handshake_and_key_exchange()
            if not success:
                self.is_connected = False
                if self.socket_conn:
                    self.socket_conn.close()
                self.activity_log.append(message)
                return False, message
            message = f"Đã kết nối đến Người nhận tại {host}:{port}"
            self.activity_log.append(message)
            return True, message
        except ConnectionRefusedError:
            self.is_connected = False
            message = "Người nhận không hoạt động hoặc địa chỉ/cổng không đúng."
            self.activity_log.append(message)
            return False, message
        except Exception as e:
            self.is_connected = False
            message = f"Lỗi khi kết nối: {e}"
            self.activity_log.append(message)
            return False, message

    def _perform_handshake_and_key_exchange(self):
        try:
            send_data_packet(self.socket_conn, {"type": "handshake", "message": "Hello!"})
            response = receive_data_packet(self.socket_conn)
            if response and response.get("type") == "handshake" and response.get("message") == "Ready!":
                pass
            else:
                message = f"Handshake thất bại: {response}"
                self.activity_log.append(message)
                raise Exception(message)

            self.session_key = get_random_bytes(24)
            self.session_iv = get_random_bytes(8)
            encrypted_session_key = rsa_encrypt(self.session_key, self.receiver_public_key)
            encrypted_session_iv = rsa_encrypt(self.session_iv, self.receiver_public_key)

            if encrypted_session_key is None or encrypted_session_iv is None:
                message = "Không thể mã hóa khóa phiên hoặc IV bằng RSA."
                self.activity_log.append(message)
                raise ValueError(message)

            metadata = {
                "timestamp": datetime.now().isoformat(),
                "sender": "SenderApp",
                "key_size": len(self.session_key) * 8,
                "iv_size": len(self.session_iv) * 8
            }
            metadata_json = json.dumps(metadata, sort_keys=True).encode('utf-8')
            signature_on_metadata = sign_data(compute_sha512(metadata_json), self.sender_private_key)

            send_data_packet(self.socket_conn, {
                "type": "key_exchange",
                "encrypted_session_key": b64encode(encrypted_session_key).decode('utf-8'),
                "encrypted_session_iv": b64encode(encrypted_session_iv).decode('utf-8'),
                "metadata": metadata,
                "signed_metadata": b64encode(signature_on_metadata).decode('utf-8')
            })

            response = receive_data_packet(self.socket_conn)
            if response and response.get("status") == "OK":
                message = "Xác thực và trao đổi khóa phiên thành công!"
                self.activity_log.append(message)
                return True, message
            else:
                message = f"Trao đổi khóa phiên thất bại: {response.get('message', 'Không rõ lỗi')}"
                self.activity_log.append(message)
                raise Exception(message)
        except Exception as e:
            self.is_connected = False
            if self.socket_conn:
                self.socket_conn.close()
            message = f"Lỗi trong quá trình Handshake hoặc Trao đổi Khóa: {e}"
            self.activity_log.append(message)
            return False, message

    def send_contract_file(self, file_content, file_name):
        if not self.is_connected or not self.socket_conn:
            message = "Chưa kết nối đến Người nhận."
            self.activity_log.append(message)
            return False, message
        if not self.sender_private_key or not self.receiver_public_key or not self.session_key:
            message = "Thiếu khóa RSA hoặc khóa phiên."
            self.activity_log.append(message)
            return False, message
        try:
            file_size = len(file_content)
            FORCED_NUM_PARTS = 3
            if file_size == 0:
                num_parts = 1
                effective_chunk_size = 0
            elif file_size < FORCED_NUM_PARTS:
                num_parts = file_size
                effective_chunk_size = 1
            else:
                num_parts = FORCED_NUM_PARTS
                effective_chunk_size = (file_size + FORCED_NUM_PARTS - 1) // FORCED_NUM_PARTS
            file_id = f"{file_name}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            file_metadata = {
                "file_id": file_id,
                "filename": file_name,
                "file_size": file_size,
                "num_parts": num_parts,
                "timestamp": datetime.now().isoformat()
            }
            file_metadata_json = json.dumps(file_metadata, sort_keys=True).encode('utf-8')
            signature_on_file_metadata = sign_data(compute_sha512(file_metadata_json), self.sender_private_key)
            send_data_packet(self.socket_conn, {
                "type": "file_init",
                "metadata": file_metadata,
                "signed_metadata": b64encode(signature_on_file_metadata).decode('utf-8')
            })
            response = receive_data_packet(self.socket_conn)
            if response and response.get("status") == "OK":
                pass
            else:
                message = f"Người nhận báo lỗi khi khởi tạo file: {response.get('message', 'Không rõ lỗi')}"
                self.activity_log.append(message)
                raise Exception(message)
            for i in range(num_parts):
                start_byte = i * effective_chunk_size
                end_byte = min((i + 1) * effective_chunk_size, file_size)
                chunk = file_content[start_byte:end_byte]
                chunk_iv = get_random_bytes(8)
                encrypted_chunk = encrypt_triple_des(chunk, self.session_key, chunk_iv)
                hash_input = chunk_iv + encrypted_chunk
                chunk_hash = compute_sha512(hash_input)
                chunk_signature = sign_data(chunk_hash, self.sender_private_key)

                # THÊM CÁC DÒNG NÀY ĐỂ GHI HASH VÀ CHỮ KÝ VÀO LOG
                self.activity_log.append(f"----- GỬI PHẦN FILE {i+1} -----")
                self.activity_log.append(f"Hash (Base64) phần {i+1}: {b64encode(chunk_hash).decode('utf-8')}")
                self.activity_log.append(f"Chữ ký (Base64) phần {i+1}: {b64encode(chunk_signature).decode('utf-8')}")
                self.activity_log.append(f"---------------------------------")
                # KẾT THÚC PHẦN THÊM MỚI

                send_data_packet(self.socket_conn, {
                    "type": "file_chunk",
                    "file_id": file_id,
                    "part_number": i,
                    "total_parts": num_parts,
                    "iv": b64encode(chunk_iv).decode('utf-8'),
                    "cipher": b64encode(encrypted_chunk).decode('utf-8'),
                    "hash": b64encode(chunk_hash).decode('utf-8'),
                    "signature": b64encode(chunk_signature).decode('utf-8')
                })
                time.sleep(0.01)
            send_data_packet(self.socket_conn, {"type": "file_end_signal", "file_id": file_id})
            final_response = receive_data_packet(self.socket_conn)
            if final_response and final_response.get("status") == "OK":
                message = f"File hợp đồng '{file_name}' (ID: {file_id}) đã được gửi và xác minh thành công!"
                self.activity_log.append(message)
                return True, message
            else:
                message = f"Người nhận báo lỗi khi hoàn tất file: {final_response.get('message', 'Không rõ lỗi')}"
                self.activity_log.append(message)
                return False, message
        except Exception as e:
            message = f"Lỗi trong quá trình gửi hợp đồng file: {e}"
            self.activity_log.append(message)
            return False, message

sender = SenderApp()

@app.route('/')
def index():
    return render_template('sender.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    success, message = sender.generate_keys(app.config['UPLOAD_FOLDER'])
    return jsonify({'success': success, 'message': message})

@app.route('/load_sender_private_key', methods=['POST'])
def load_sender_private_key():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'Không có file được tải lên'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'Không có file được chọn'})
    filename = os.path.join(app.config['UPLOAD_FOLDER'], 'sender_private_key.pem')
    file.save(filename)
    success, message = sender.load_sender_private_key(filename)
    return jsonify({'success': success, 'message': message})

@app.route('/load_receiver_public_key', methods=['POST'])
def load_receiver_public_key():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'Không có file được tải lên'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'Không có file được chọn'})
    filename = os.path.join(app.config['UPLOAD_FOLDER'], 'receiver_public_key.pem')
    file.save(filename)
    success, message = sender.load_receiver_public_key(filename)
    return jsonify({'success': success, 'message': message})

@app.route('/connect', methods=['POST'])
def connect():
    data = request.get_json()
    host = data.get('host')
    port = int(data.get('port'))
    success, message = sender.connect_to_receiver(host, port)
    return jsonify({'success': success, 'message': message})

@app.route('/send_file', methods=['POST'])
def send_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'Không có file được tải lên'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'Không có file được chọn'})
    file_content = file.read()
    file_name = file.filename
    success, message = sender.send_contract_file(file_content, file_name)
    return jsonify({'success': success, 'message': message})

@app.route('/get_logs', methods=['GET'])
def get_logs():
    return jsonify({'logs': sender.activity_log})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)