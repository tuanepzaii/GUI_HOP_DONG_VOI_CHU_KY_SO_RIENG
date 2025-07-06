import json
import socket
from base64 import b64encode, b64decode
from Crypto import Random
from Crypto.Cipher import DES3, PKCS1_v1_5 # Thêm PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad, unpad # Import cho padding Triple DES
import os

# Kích thước bộ đệm cho socket khi nhận/gửi dữ liệu
BUFFER_SIZE = 4096 # 4KB

# Kích thước khóa RSA mặc định (bits)
RSA_KEY_SIZE = 2048 

def get_random_bytes(num_bytes):
    """Tạo số byte ngẫu nhiên an toàn bằng mật mã."""
    return Random.get_random_bytes(num_bytes)

def generate_rsa_keys(private_key_path, public_key_path, key_size=RSA_KEY_SIZE):
    """
    Tạo cặp khóa RSA (khóa riêng tư và khóa công khai) và lưu vào file PEM.

    Args:
        private_key_path (str): Đường dẫn để lưu khóa riêng tư.
        public_key_path (str): Đường dẫn để lưu khóa công khai.
        key_size (int): Kích thước khóa RSA tính bằng bit. Mặc định là 2048.
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    os.makedirs(os.path.dirname(private_key_path) or '.', exist_ok=True)
    with open(private_key_path, "wb") as f:
        f.write(private_key)
    
    os.makedirs(os.path.dirname(public_key_path) or '.', exist_ok=True)
    with open(public_key_path, "wb") as f:
        f.write(public_key)

def load_rsa_private_key(file_path):
    """
    Tải khóa riêng tư RSA từ file PEM.

    Args:
        file_path (str): Đường dẫn đến file khóa riêng tư.

    Returns:
        Crypto.PublicKey.RSA._RSAobj: Đối tượng khóa riêng tư RSA.
    """
    with open(file_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    return private_key

def load_rsa_public_key(file_path):
    """
    Tải khóa công khai RSA từ file PEM.

    Args:
        file_path (str): Đường dẫn đến file khóa công khai.

    Returns:
        Crypto.PublicKey.RSA._RSAobj: Đối tượng khóa công khai RSA.
    """
    with open(file_path, "rb") as f:
        public_key = RSA.import_key(f.read())
    return public_key

def rsa_encrypt(data, public_key):
    """
    Mã hóa dữ liệu bằng khóa công khai RSA (sử dụng PKCS1_v1_5).

    Args:
        data (bytes): Dữ liệu cần mã hóa.
        public_key (Crypto.PublicKey.RSA._RSAobj): Đối tượng khóa công khai RSA.

    Returns:
        bytes: Dữ liệu đã mã hóa.
    """
    cipher_rsa = PKCS1_v1_5.new(public_key)
    return cipher_rsa.encrypt(data)

def rsa_decrypt(encrypted_data, private_key):
    """
    Giải mã dữ liệu bằng khóa riêng tư RSA (sử dụng PKCS1_v1_5).

    Args:
        encrypted_data (bytes): Dữ liệu đã mã hóa.
        private_key (Crypto.PublicKey.RSA._RSAobj): Đối tượng khóa riêng tư RSA.

    Returns:
        bytes: Dữ liệu đã giải mã.
    """
    cipher_rsa = PKCS1_v1_5.new(private_key)
    # Độ dài dữ liệu mã hóa phải bằng kích thước khóa RSA (tính bằng byte)
    # Ví dụ: khóa 2048 bit = 256 bytes
    # Tuy nhiên, PKCS1_v1_5.decrypt có thể tự xử lý padding và trả về lỗi nếu không hợp lệ
    # Do đó, chỉ cần truyền dữ liệu mã hóa vào.
    return cipher_rsa.decrypt(encrypted_data, None) # None là random_bytes_generator, không dùng cho decrypt

def encrypt_triple_des(data, key, iv, include_iv_in_output=False):
    """
    Mã hóa dữ liệu bằng Triple DES ở chế độ CBC.

    Args:
        data (bytes): Dữ liệu cần mã hóa.
        key (bytes): Khóa Triple DES (16 hoặc 24 bytes).
        iv (bytes): IV (Initialization Vector) cho CBC (8 bytes).
        include_iv_in_output (bool): Nếu True, IV sẽ được gắn vào đầu ciphertext.

    Returns:
        bytes: Dữ liệu đã mã hóa. Nếu include_iv_in_output là True, trả về IV + Ciphertext.
    """
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_data = pad(data, DES3.block_size) # Đệm dữ liệu
    ciphertext = cipher.encrypt(padded_data)
    
    if include_iv_in_output:
        return iv + ciphertext
    return ciphertext

def decrypt_triple_des(encrypted_data, key, iv, unpad_output=False):
    """
    Giải mã dữ liệu bằng Triple DES ở chế độ CBC.

    Args:
        encrypted_data (bytes): Dữ liệu đã mã hóa (có thể bao gồm IV ở đầu).
        key (bytes): Khóa Triple DES (16 hoặc 24 bytes).
        iv (bytes): IV (Initialization Vector) cho CBC (8 bytes).
        unpad_output (bool): Nếu True, sẽ loại bỏ padding sau khi giải mã.

    Returns:
        bytes: Dữ liệu đã giải mã.
    """
    # Nếu encrypted_data bao gồm IV ở đầu, bạn cần tách nó ra trước khi tạo cipher
    # Logic này cần được xử lý ở nơi gọi hàm nếu IV được gắn vào ciphertext
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_padded_data = cipher.decrypt(encrypted_data)
    
    if unpad_output:
        return unpad(decrypted_padded_data, DES3.block_size) # Bỏ đệm dữ liệu
    return decrypted_padded_data


def compute_sha512(data):
    """
    Tính toán hàm băm SHA512 của dữ liệu.

    Args:
        data (bytes): Dữ liệu cần băm.

    Returns:
        bytes: Giá trị băm SHA512.
    """
    h = SHA512.new()
    h.update(data)
    return h.digest()

def sign_data(data_hash, private_key):
    """
    Ký giá trị băm của dữ liệu bằng khóa riêng tư RSA.

    Args:
        data_hash (bytes): Giá trị băm của dữ liệu cần ký (ví dụ: SHA512).
        private_key (Crypto.PublicKey.RSA._RSAobj): Đối tượng khóa riêng tư RSA.

    Returns:
        bytes: Chữ ký số.
    """
    signer = pkcs1_15.new(private_key)
    return signer.sign(SHA512.new(data_hash)) # pkcs1_15.sign mong đợi một đối tượng hash

def verify_signature(data_hash, signature, public_key):
    """
    Xác minh chữ ký số của dữ liệu bằng khóa công khai RSA.

    Args:
        data_hash (bytes): Giá trị băm của dữ liệu đã ký (ví dụ: SHA512).
        signature (bytes): Chữ ký số cần xác minh.
        public_key (Crypto.PublicKey.RSA._RSAobj): Đối tượng khóa công khai RSA.

    Returns:
        bool: True nếu chữ ký hợp lệ, False nếu không hợp lệ.
    """
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(SHA512.new(data_hash), signature) # pkcs1_15.verify mong đợi một đối tượng hash
        return True
    except (ValueError, TypeError):
        return False

def send_data_packet(sock, data_dict):
    """
    Gửi một gói dữ liệu qua socket sau khi mã hóa JSON và thêm tiền tố độ dài.

    Args:
        sock (socket.socket): Đối tượng socket đã kết nối.
        data_dict (dict): Dữ liệu Python dictionary cần gửi.
    """
    json_data = json.dumps(data_dict)
    # Thêm tiền tố độ dài 4 bytes (big-endian) cho gói dữ liệu
    length_prefix = len(json_data).to_bytes(4, 'big')
    sock.sendall(length_prefix + json_data.encode('utf-8'))

def receive_data_packet(sock):
    """
    Nhận một gói dữ liệu từ socket theo định dạng tiền tố độ dài.

    Args:
        sock (socket.socket): Đối tượng socket đã kết nối.

    Returns:
        dict or None: Dữ liệu đã giải mã JSON dưới dạng từ điển, hoặc None nếu có lỗi/kết nối đóng.
    """
    try:
        # Nhận 4 bytes đầu tiên để biết độ dài gói dữ liệu
        length_bytes = sock.recv(4)
        if not length_bytes:
            return None # Kết nối bị đóng hoặc lỗi
        
        data_length = int.from_bytes(length_bytes, 'big')
        
        # Nhận đủ dữ liệu theo độ dài đã cho
        received_data = b""
        while len(received_data) < data_length:
            # Đảm bảo không nhận quá nhiều nếu BUFFER_SIZE lớn hơn phần còn lại
            packet = sock.recv(min(data_length - len(received_data), BUFFER_SIZE))
            if not packet:
                return None # Kết nối bị đóng hoặc lỗi
            received_data += packet
        
        return json.loads(received_data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Lỗi giải mã gói dữ liệu JSON/Unicode: {e}")
        return None
    except socket.error as e:
        print(f"Lỗi socket khi nhận dữ liệu: {e}")
        return None
    except Exception as e:
        print(f"Lỗi không xác định khi nhận dữ liệu: {e}")
        return None