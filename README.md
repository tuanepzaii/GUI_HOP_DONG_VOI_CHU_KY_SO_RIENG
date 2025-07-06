1. Giới thiệu
Trong bối cảnh chuyển đổi số và yêu cầu bảo mật thông tin ngày càng cao, việc ứng dụng chữ ký số trong giao tiếp dữ liệu là cần thiết. Đề tài “Gửi hợp đồng với chữ ký số riêng” đã được hiện thực hóa dưới dạng giao diện web để tăng tính trực quan và dễ sử dụng cho người dùng.

Web ứng dụng được xây dựng bằng Flask – một micro framework của Python – có khả năng chạy trực tiếp trên trình duyệt. Qua đó, toàn bộ quá trình: ký hợp đồng, mã hóa, gửi dữ liệu, nhận và xác thực... đều có thể thao tác thông qua giao diện đơn giản, thân thiện.

2. Trình bày kỹ thuật

2.1 Ngôn ngữ và thư viện sử dụng
Python 3.x

Flask – Framework web

PyCryptodome – Thư viện mã hóa: RSA, SHA-512, Triple DES

HTML + Bootstrap – Giao diện frontend

2.2 Luồng hoạt động trên giao diện web
Người dùng chọn file hợp đồng (contract.txt)

Nhấn nút "Gửi hợp đồng":

Sinh khóa RSA (nếu chưa có)

Ký metadata

Tạo session key và mã hóa bằng RSA

Chia file thành 3 phần, mã hóa bằng Triple DES

Tính SHA-512, ký từng phần, tạo gói tin JSON

Nhấn "Nhận hợp đồng":

Giải mã session key

Xác thực từng phần qua chữ ký số và hash

Nếu hợp lệ: giải mã + ghép thành contract_out.txt

Trả về kết quả (ACK hoặc NACK)

3. Hình ảnh minh họa

Giao diện chính của web:
![image](https://github.com/user-attachments/assets/f013ad38-6b5b-4a62-829d-d2f11c0f2a8e)
![image](https://github.com/user-attachments/assets/67b2943c-baaa-478c-8e81-75f574c7e263)



Gồm 2 nút chính: "Gửi hợp đồng" và "Nhận hợp đồng"

Hộp thoại chọn file hợp đồng

Thông báo trạng thái: "✅ Gửi thành công" hoặc "❌ Chữ ký không hợp lệ"

Nội dung của contract_out.txt sau khi giải mã thành công

4. Hướng dẫn chạy ứng dụng
4.1 Cài đặt thư viện
Mở CMD hoặc Terminal, chạy:
pip install flask pycryptodome
4.2 Cấu trúc thư mục
project/
├── app.py                # Flask server
├── templates/
│   └── index.html        # Giao diện người dùng
├── sender_utils.py       # Các hàm mã hóa + gửi
├── receiver_utils.py     # Các hàm giải mã + kiểm tra
├── contract.txt          # File đầu vào
├── encrypted_key.bin     # Khóa phiên đã mã hóa
├── packages.txt          # 3 phần gói tin mã hóa
├── contract_out.txt      # File kết quả sau khi nhận
4.3 Chạy chương trình
python app.py
Truy cập trên trình duyệt:

http://127.0.0.1:5000
5. Hướng phát triển
🔐 Thêm xác thực người dùng (Login) để đảm bảo chỉ người được cấp quyền mới được gửi/nhận hợp đồng.

📁 Cho phép gửi nhiều loại file: PDF, DOCX thay vì chỉ hỗ trợ TXT.

📡 Triển khai online (deploy) trên Heroku hoặc Render để dùng trên Internet.

📄 Tự động sinh biên bản chứng thực (PDF) sau khi ký và xác minh hợp đồng.

📊 Lưu lịch sử giao dịch: gửi, nhận, thất bại, thành công.
6. Tác giả
Họ tên: Phạm Đình Tuấn
Lớp: CNTT16-05
Môn: An toàn và Bảo mật thông tin
GVHD: Trần Đức Thắng
