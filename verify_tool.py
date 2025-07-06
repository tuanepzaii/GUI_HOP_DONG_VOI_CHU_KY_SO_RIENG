import os
from base64 import b64decode
# Đảm bảo utils.py nằm cùng thư mục hoặc trong PYTHONPATH
from utils import load_rsa_public_key, verify_signature, compute_sha512 

def run_verification_tool():
    print("\n--- Công cụ Xác minh Chữ ký File (Offline) ---")
    print("-------------------------------------------------")
    print("Công cụ này giúp bạn xác minh tính toàn vẹn và xác thực của một file hoặc một hash.")
    print("Để hoạt động, bạn cần cung cấp:")
    print("  1. Đường dẫn đến file cần xác minh (để đọc nội dung, nếu cần hash lại).")
    print("  2. Đường dẫn đến khóa công khai của người đã ký.")
    print("  3. CHUỖI BASE64 CỦA HASH GỐC (Hash của IV || Ciphertext từ log Người gửi).")
    print("  4. CHUỖI BASE64 CỦA CHỮ KÝ SỐ GỐC (từ log Người gửi).")
    print("-------------------------------------------------\n")

    # 1. Nhập đường dẫn đến file cần xác minh (chỉ để tham khảo, không dùng để tính hash)
    file_path = input("Nhập đường dẫn đến file đã nhận (ví dụ: received_files\\New Text Document.txt): ").strip()
    if not os.path.exists(file_path):
        print(f"Cảnh báo: Không tìm thấy file tại đường dẫn: {file_path}. Công cụ sẽ không thể đọc nội dung file.")
        # Không return, vì có thể người dùng chỉ muốn xác minh hash trực tiếp.
    else:
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            print(f"Đã đọc file: {os.path.basename(file_path)} ({len(file_content)} bytes)")
        except Exception as e:
            print(f"Lỗi khi đọc file: {e}")
            file_content = None # Đảm bảo file_content là None nếu có lỗi

    # 2. Nhập đường dẫn đến khóa công khai của người gửi
    public_key_path = input("Nhập đường dẫn đến khóa công khai của người gửi (ví dụ: keys\\sender_public_key.pem): ").strip()
    sender_public_key = load_rsa_public_key(public_key_path)
    if not sender_public_key:
        print(f"Lỗi: Không thể tải khóa công khai từ: {public_key_path}")
        return
    print(f"Đã tải khóa công khai từ: {os.path.basename(public_key_path)}")

    print("\n--- Lưu ý quan trọng ---")
    print("Công cụ này được điều chỉnh để xác minh hash của (IV || ciphertext) của MỘT PHẦN file.")
    print("Đảm bảo bạn sao chép đúng 'Hash (Base64)' và 'Chữ ký (Base64)' từ log của Người gửi.")
    print("------------------------\n")

    # 3. Nhập chuỗi Base64 của Hash gốc (Hash của IV || Ciphertext)
    hash_b64_to_verify = input("Nhập chuỗi Base64 của HASH GỐC (từ log của Người gửi): ").strip()
    if not hash_b64_to_verify:
        print("Lỗi: Chuỗi hash không được để trống.")
        return
    
    try:
        # Giải mã chuỗi Base64 để lấy byte của hash
        hash_to_verify = b64decode(hash_b64_to_verify)
        print("Đã giải mã chuỗi hash Base64.")
    except Exception as e:
        print(f"Lỗi: Chuỗi hash Base64 không hợp lệ. {e}")
        print("Vui lòng đảm bảo bạn đã sao chép đúng chuỗi Base64 của hash.")
        return

    # 4. Nhập chuỗi Base64 của chữ ký số
    signature_b64 = input("Nhập chuỗi Base64 của CHỮ KÝ SỐ (từ log của Người gửi): ").strip()
    if not signature_b64:
        print("Lỗi: Chuỗi chữ ký không được để trống.")
        return

    try:
        signature = b64decode(signature_b64)
        print("Đã giải mã chuỗi chữ ký Base64.")
    except Exception as e:
        print(f"Lỗi: Chuỗi chữ ký Base64 không hợp lệ. {e}")
        print("Vui lòng đảm bảo bạn đã sao chép đúng chuỗi Base64 của chữ ký.")
        return

    print("\nĐang thực hiện xác minh...")
    try:
        # Xác minh chữ ký với HASH TRỰC TIẾP đã nhập
        if verify_signature(hash_to_verify, signature, sender_public_key):
            print("\n[THÀNH CÔNG] Chữ ký hợp lệ!")
            print("=> Hash này đúng là do người gửi đã ký bằng khóa riêng tư tương ứng.")
            print("=> Điều này gián tiếp xác nhận tính toàn vẹn của (IV || Ciphertext) của phần file tương ứng.")
        else:
            print("\n[THẤT BẠI] Chữ ký không hợp lệ!")
            print("=> Hash hoặc chữ ký không đúng, hoặc khóa công khai không khớp.")
    except Exception as e:
        print(f"\nLỗi trong quá trình xác minh: {e}")

if __name__ == "__main__":
    run_verification_tool()