import socket
import os
import json
import time
from datetime import datetime
from base64 import b64encode, b64decode
import threading
from flask import Flask, render_template, request, jsonify

from utils import (
    load_rsa_private_key, load_rsa_public_key,
    decrypt_triple_des, rsa_decrypt,
    verify_signature, send_data_packet, receive_data_packet,
    BUFFER_SIZE, generate_rsa_keys,
    compute_sha512
)

app = Flask(__name__, template_folder='templates')
app.config['UPLOAD_FOLDER'] = 'keys'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

class ReceiverApp:
    def __init__(self):
        self.receiver_private_key = None
        self.sender_public_key = None
        self.server_socket = None
        self.running = False
        self.client_sessions = {}
        self.activity_log = []  # Danh sách để lưu nhật ký hoạt động

    def generate_keys(self, output_dir):
        private_path = os.path.join(output_dir, "receiver_private_key.pem")
        public_path = os.path.join(output_dir, "receiver_public_key.pem")
        try:
            generate_rsa_keys(private_path, public_path)
            message = f"Đã tạo khóa tại: {output_dir}"
            self.activity_log.append(message)
            return True, message
        except Exception as e:
            message = f"Lỗi khi tạo khóa: {e}"
            self.activity_log.append(message)
            return False, message

    def load_receiver_private_key(self, file_path):
        key = load_rsa_private_key(file_path)
        if key:
            self.receiver_private_key = key
            message = f"Đã tải khóa riêng tư người nhận từ: {file_path}"
            self.activity_log.append(message)
            return True, message
        message = f"Không thể tải khóa riêng tư người nhận từ: {file_path}"
        self.activity_log.append(message)
        return False, message

    def load_sender_public_key(self, file_path):
        key = load_rsa_public_key(file_path)
        if key:
            self.sender_public_key = key
            message = f"Đã tải khóa công khai người gửi từ: {file_path}"
            self.activity_log.append(message)
            return True, message
        message = f"Không thể tải khóa công khai người gửi từ: {file_path}"
        self.activity_log.append(message)
        return False, message

    def start_server(self, port):
        if self.running:
            message = "Server đang chạy."
            self.activity_log.append(message)
            return False, message
        if not self.receiver_private_key or not self.sender_public_key:
            message = "Thiếu khóa RSA để khởi động server."
            self.activity_log.append(message)
            return False, message
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.settimeout(1.0)
            self.server_socket.bind(('', port))
            self.server_socket.listen(5)
            self.running = True
            threading.Thread(target=self._start_server_task, daemon=True).start()
            message = f"Server đang lắng nghe tại cổng {port}..."
            self.activity_log.append(message)
            return True, message
        except Exception as e:
            message = f"Lỗi khởi động server: {e}"
            self.activity_log.append(message)
            return False, message

    def stop_server(self):
        if not self.running:
            message = "Server không chạy."
            self.activity_log.append(message)
            return False, message
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
                self.server_socket.close()
            except OSError as e:
                message = f"Lỗi khi đóng server socket: {e}"
                self.activity_log.append(message)
                return False, message
            finally:
                self.server_socket = None
        message = "Server đã dừng."
        self.activity_log.append(message)
        return True, message

    def _start_server_task(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                self.activity_log.append(f"Đã chấp nhận kết nối từ {addr}")
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                client_thread.start()
            except socket.timeout:
                pass
            except OSError:
                break
            except Exception as e:
                if self.running:
                    self.activity_log.append(f"Lỗi chấp nhận kết nối: {e}")
        self.activity_log.append("Server đã dừng.")

    def handle_client(self, conn, addr):
        self.client_sessions[addr] = {
            "session_key": None,
            "session_iv": None,
            "receiving_files": {}
        }
        try:
            while True:
                data_packet = receive_data_packet(conn)
                if not data_packet:
                    break
                packet_type = data_packet.get("type")
                if packet_type == "handshake":
                    message = data_packet.get("message")
                    if message == "Hello!":
                        send_data_packet(conn, {"type": "handshake", "message": "Ready!"})
                        self.activity_log.append(f"Handshake thành công với {addr}")
                    else:
                        send_data_packet(conn, {"type": "handshake", "status": "ERROR", "message": "Invalid handshake message."})
                        self.activity_log.append(f"Handshake thất bại với {addr}: Invalid handshake message")
                elif packet_type == "key_exchange":
                    encrypted_session_key_b64 = data_packet.get("encrypted_session_key")
                    encrypted_session_iv_b64 = data_packet.get("encrypted_session_iv")
                    metadata = data_packet.get("metadata")
                    signed_metadata_b64 = data_packet.get("signed_metadata")
                    try:
                        signed_metadata = b64decode(signed_metadata_b64)
                        metadata_json = json.dumps(metadata, sort_keys=True).encode('utf-8')
                        if not verify_signature(compute_sha512(metadata_json), signed_metadata, self.sender_public_key):
                            raise ValueError("Xác minh chữ ký metadata trao đổi khóa KHÔNG thành công.")
                        session_key = rsa_decrypt(b64decode(encrypted_session_key_b64), self.receiver_private_key)
                        session_iv = rsa_decrypt(b64decode(encrypted_session_iv_b64), self.receiver_private_key)
                        if session_key is None or session_iv is None:
                            raise ValueError("Không thể giải mã khóa phiên hoặc IV.")
                        self.client_sessions[addr]["session_key"] = session_key
                        self.client_sessions[addr]["session_iv"] = session_iv
                        send_data_packet(conn, {"status": "OK", "message": "Xác thực và trao đổi khóa phiên thành công."})
                        self.activity_log.append(f"Trao đổi khóa phiên thành công với {addr}")
                    except Exception as e:
                        send_data_packet(conn, {"status": "ERROR", "message": f"Lỗi trao đổi khóa: {e}"})
                        self.activity_log.append(f"Lỗi trao đổi khóa với {addr}: {e}")
                        break
                elif packet_type == "file_init":
                    metadata = data_packet.get("metadata")
                    signed_metadata_b64 = data_packet.get("signed_metadata")
                    file_id = metadata.get("file_id")
                    if not file_id:
                        send_data_packet(conn, {"status": "ERROR", "message": "Gói khởi tạo file không hợp lệ: thiếu file_id."})
                        self.activity_log.append(f"Lỗi khởi tạo file từ {addr}: Thiếu file_id")
                        continue
                    try:
                        signed_metadata = b64decode(signed_metadata_b64)
                        metadata_json = json.dumps(metadata, sort_keys=True).encode('utf-8')
                        if not verify_signature(compute_sha512(metadata_json), signed_metadata, self.sender_public_key):
                            raise ValueError("Xác minh chữ ký metadata file tổng quát KHÔNG thành công.")
                        self.client_sessions[addr]["receiving_files"][file_id] = {
                            "metadata": metadata,
                            "chunks": {},
                            "received_parts": 0
                        }
                        send_data_packet(conn, {"status": "OK", "message": "Thông tin file khởi tạo đã được nhận và xác minh."})
                        self.activity_log.append(f"Khởi tạo file '{metadata['filename']}' (ID: {file_id}) từ {addr}")
                    except Exception as e:
                        send_data_packet(conn, {"status": "ERROR", "message": f"Lỗi khởi tạo file: {e}"})
                        self.activity_log.append(f"Lỗi khởi tạo file '{file_id}' từ {addr}: {e}")
                        if file_id in self.client_sessions[addr]["receiving_files"]:
                            del self.client_sessions[addr]["receiving_files"][file_id]
                elif packet_type == "file_chunk":
                    file_id = data_packet.get("file_id")
                    part_number = data_packet.get("part_number")
                    iv_b64 = data_packet.get("iv")
                    cipher_b64 = data_packet.get("cipher")
                    hash_b64 = data_packet.get("hash")
                    signature_b64 = data_packet.get("signature")
                    if file_id not in self.client_sessions[addr]["receiving_files"]:
                        send_data_packet(conn, {"status": "ERROR", "message": "File ID không hợp lệ hoặc chưa khởi tạo."})
                        self.activity_log.append(f"Lỗi xử lý phần file từ {addr}: File ID {file_id} không hợp lệ")
                        continue
                    current_file_info = self.client_sessions[addr]["receiving_files"][file_id]
                    try:
                        session_key = self.client_sessions[addr]["session_key"]
                        if session_key is None:
                            raise ValueError("Khóa phiên chưa được thiết lập cho client này.")
                        iv_bytes = b64decode(iv_b64)
                        cipher_bytes = b64decode(cipher_b64)
                        received_hash_bytes = b64decode(hash_b64)
                        signature_bytes = b64decode(signature_b64)
                        hash_input_for_verification = iv_bytes + cipher_bytes
                        re_computed_hash = compute_sha512(hash_input_for_verification)
                        if re_computed_hash != received_hash_bytes:
                            raise ValueError(f"Hash của phần {part_number} KHÔNG khớp. File có thể bị thay đổi.")
                        if not verify_signature(re_computed_hash, signature_bytes, self.sender_public_key):
                            raise ValueError(f"Chữ ký của phần {part_number} KHÔNG hợp lệ. Xác thực thất bại.")
                        decrypted_chunk = decrypt_triple_des(cipher_bytes, session_key, iv_bytes)
                        current_file_info["chunks"][part_number] = decrypted_chunk
                        current_file_info["received_parts"] += 1
                        self.activity_log.append(f"Đã nhận phần {part_number + 1}/{current_file_info['metadata']['num_parts']} của file '{current_file_info['metadata']['filename']}' từ {addr}")
                    except Exception as e:
                        send_data_packet(conn, {"status": "ERROR", "message": f"Lỗi xử lý phần file {part_number}: {e}"})
                        self.activity_log.append(f"Lỗi xử lý phần {part_number} của file '{file_id}' từ {addr}: {e}")
                        if file_id in self.client_sessions[addr]["receiving_files"]:
                            del self.client_sessions[addr]["receiving_files"][file_id]
                elif packet_type == "file_end_signal":
                    file_id = data_packet.get("file_id")
                    if file_id in self.client_sessions[addr]["receiving_files"]:
                        file_info = self.client_sessions[addr]["receiving_files"][file_id]
                        total_parts = file_info["metadata"]["num_parts"]
                        received_parts = file_info["received_parts"]
                        if received_parts == total_parts:
                            success, message = self.complete_file_reception(conn, addr, file_id)
                            self.activity_log.append(message)
                        else:
                            message = f"File '{file_info['metadata']['filename']}' bị thiếu phần."
                            send_data_packet(conn, {"status": "ERROR", "message": message})
                            self.activity_log.append(message)
                            del self.client_sessions[addr]["receiving_files"][file_id]
                    else:
                        message = f"File ID {file_id} không tồn tại hoặc đã xử lý."
                        send_data_packet(conn, {"status": "OK", "message": message})
                        self.activity_log.append(message)
        except socket.error:
            self.activity_log.append(f"Kết nối với {addr} đã đóng.")
        finally:
            conn.close()
            if addr in self.client_sessions:
                del self.client_sessions[addr]

    def complete_file_reception(self, conn, addr, file_id):
        if file_id not in self.client_sessions[addr]["receiving_files"]:
            send_data_packet(conn, {"status": "ERROR", "message": "File không tồn tại để hoàn tất."})
            message = f"Không tìm thấy file ID {file_id} để hoàn tất từ {addr}."
            self.activity_log.append(message)
            return False, message
        file_info = self.client_sessions[addr]["receiving_files"][file_id]
        chunks = file_info["chunks"]
        metadata = file_info["metadata"]
        filename = metadata["filename"]
        total_parts = metadata["num_parts"]
        received_parts = file_info["received_parts"]
        try:
            if received_parts < total_parts:
                message = f"Thiếu các phần file. Dự kiến {total_parts}, đã nhận {received_parts}."
                send_data_packet(conn, {"status": "ERROR", "message": message})
                del self.client_sessions[addr]["receiving_files"][file_id]
                self.activity_log.append(message)
                return False, message
            ordered_chunks = [chunks[i] for i in sorted(chunks.keys())]
            reconstructed_file_content = b''.join(ordered_chunks)
            save_dir = "received_files"
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, filename)
            with open(save_path, "wb") as f:
                f.write(reconstructed_file_content)
            message = f"File '{filename}' (ID: {file_id}) đã được nhận, giải mã và lưu vào: {save_path}"
            send_data_packet(conn, {"status": "OK", "message": f"File '{filename}' đã được nhận và lưu."})
            del self.client_sessions[addr]["receiving_files"][file_id]
            self.activity_log.append(message)
            return True, message
        except Exception as e:
            message = f"Lỗi hoàn tất truyền file '{filename}' (ID: {file_id}): {e}"
            send_data_packet(conn, {"status": "ERROR", "message": message})
            if file_id in self.client_sessions[addr]["receiving_files"]:
                del self.client_sessions[addr]["receiving_files"][file_id]
            self.activity_log.append(message)
            return False, message

receiver = ReceiverApp()

@app.route('/')
def index():
    return render_template('receiver.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    success, message = receiver.generate_keys(app.config['UPLOAD_FOLDER'])
    return jsonify({'success': success, 'message': message})

@app.route('/load_receiver_private_key', methods=['POST'])
def load_receiver_private_key():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'Không có file được tải lên'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'Không có file được chọn'})
    filename = os.path.join(app.config['UPLOAD_FOLDER'], 'receiver_private_key.pem')
    file.save(filename)
    success, message = receiver.load_receiver_private_key(filename)
    return jsonify({'success': success, 'message': message})

@app.route('/load_sender_public_key', methods=['POST'])
def load_sender_public_key():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'Không có file được tải lên'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'Không có file được chọn'})
    filename = os.path.join(app.config['UPLOAD_FOLDER'], 'sender_public_key.pem')
    file.save(filename)
    success, message = receiver.load_sender_public_key(filename)
    return jsonify({'success': success, 'message': message})

@app.route('/start_server', methods=['POST'])
def start_server():
    data = request.get_json()
    port = int(data.get('port'))
    success, message = receiver.start_server(port)
    return jsonify({'success': success, 'message': message})

@app.route('/stop_server', methods=['POST'])
def stop_server():
    success, message = receiver.stop_server()
    return jsonify({'success': success, 'message': message})

@app.route('/get_logs', methods=['GET'])
def get_logs():
    return jsonify({'logs': receiver.activity_log})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)