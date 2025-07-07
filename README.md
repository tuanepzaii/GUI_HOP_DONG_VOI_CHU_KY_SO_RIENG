# 🚀 GỬI HỢP ĐỒNG VỚI CHỮ KÝ SỐ RIÊNG

<p align="center">
  <img src="logoDaiNam.png" alt="DaiNam University Logo" width="250"/>
</p>

## **✨ Giới thiệu dự án**


Đây là dự án bài tập lớn môn An Toàn Bảo Mật Thông Tin, tập trung xây dựng một hệ thống truyền tải file hợp đồng an toàn giữa Người gửi (Sender) và Người nhận (Receiver).

Dự án hiện thực hóa Đề tài 3: **Gửi hợp đồng với chữ ký số riêng** đảm bảo các yếu tố cốt lõi:

🔒 Bảo mật (Confidentiality): Giữ bí mật tuyệt đối nội dung file.

✅ Toàn vẹn (Integrity): Đảm bảo file không bị thay đổi trên đường truyền.

🤝 Xác thực (Authentication): Xác nhận file đến từ đúng người gửi.

**Hệ thống của chúng tôi cho phép bạn**

🔑 Tạo và quản lý các cặp khóa RSA một cách dễ dàng.

🔗 Thiết lập kết nối an toàn giữa Người gửi và Người nhận.

✂️ Chia nhỏ file hợp đồng, sao đó mã hóa và ký số riêng từng phần trước khi gửi đi.

🔍 Người nhận có thể xác minh tính toàn vẹn và xác thực của từng phần file, giải mã và tái tạo file gốc.

🛠️ Cung cấp công cụ xác minh offline tiện lợi để kiểm tra chữ ký số độc lập.

## **🏗️ Cấu trúc dự án**


Dự án được tổ chức gọn gàng và logic với các thành phần chính:

**receiver_app.py:** Ứng dụng Người nhận (Receiver).

🌐 Giao diện web và logic xử lý nhận, giải mã, xác minh file.

🔑 Tích hợp chức năng tạo khóa RSA cho người nhận.

**sender_app.py:** Ứng dụng Người gửi (Sender).

🌐 Giao diện web và logic xử lý kết nối, mã hóa, ký số và gửi file.

🔑 Tích hợp chức năng tạo khóa RSA cho người gửi.

**utils.py:** Module chứa các hàm tiện ích mật mã và mạng dùng chung.

**verify_tool.py:** Công cụ Python độc lập (offline) để xác minh chữ ký số.

**keys/:** Thư mục lưu trữ các cặp khóa RSA (.pem).

**received_files/:** Nơi lưu trữ các file đã nhận và giải mã thành công.

**templates/:** Chứa các tệp mẫu HTML cho giao diện web.

**contract.txt:** Tệp dữ liệu mẫu dùng để thử nghiệm.

**myenv/ (hoặc .venv/):** Môi trường ảo Python của dự án.

**🛠️ Kỹ thuật và Thuật toán sử dụng**


Hệ thống được xây dựng bằng Python 3.13.5 và áp dụng các công nghệ, thuật toán mật mã tiên tiến:

**PyCryptodome:** Thư viện mật mã chủ chốt:

**Triple DES (3DES):** Thuật toán mã hóa đối xứng, dùng để mã hóa nội dung file.

Sử dụng chế độ CBC (Cipher Block Chaining) với IV ngẫu nhiên để tăng cường bảo mật và che giấu mẫu dữ liệu.

**RSA 2048-bit:** Thuật toán mã hóa bất đối xứng.

Trao đổi khóa phiên an toàn: Mã hóa khóa phiên 3DES bằng khóa công khai của người nhận.

Tạo và xác minh chữ ký số: Ký metadata và từng phần file bằng khóa riêng tư của người gửi.

Sử dụng chế độ đệm PKCS#1 v1.5 để đảm bảo an toàn.

**SHA-512:** Hàm băm mật mã mạnh mẽ, dùng để:

Kiểm tra tính toàn vẹn: Tạo giá trị băm của (IV || ciphertext) của từng phần file.

Đầu vào cho chữ ký số: Giá trị băm này được ký bằng RSA.

**Chữ ký số (Digital Signature):** Sự kết hợp giữa RSA và SHA-512, đảm bảo tính xác thực và không chối bỏ.

**Flask:** Micro-framework Python, tạo giao diện người dùng dạng web thân thiện.

**Socket:** Thư viện chuẩn Python, thiết lập kết nối mạng TCP giữa hai bên.

**Các thư viện Python tiêu chuẩn khác:** json, base64, os, datetime, threading, math hỗ trợ xử lý dữ liệu, quản lý file, thời gian và đa luồng.

## **🖥️ Giao diện ứng dụng**


Hệ thống cung cấp hai giao diện web trực quan cho SenderApp và ReceiverApp, dễ dàng truy cập qua trình duyệt.

**Giao diện SenderApp**
Tiêu đề:**"ỨNG DỤNG NGƯỜI GỬI HỢP ĐỒNG"**

![image](https://github.com/user-attachments/assets/288de54e-e909-45ab-bcd8-1aaa8bec6131)


**Các thành phần chính:**

🔑 Quản Lý Khóa RSA: Tạo và tải khóa RSA (riêng tư của người gửi, công khai của người nhận).

🔗 Kết Nối Với Người Nhận: Nhập địa chỉ và cổng để thiết lập kết nối.

✉️ Gửi Hợp Đồng: Chọn file và bắt đầu quá trình mã hóa, ký số, gửi.

📜 Nhật Ký Hoạt Động: Hiển thị chi tiết quá trình, bao gồm Hash (Base64) và Chữ ký (Base64) của từng phần file.

**Giao diện ReceiverApp**
Tiêu đề: **"ỨNG DỤNG NGƯỜI NHẬN HỢP ĐỒNG"**

![image](https://github.com/user-attachments/assets/28f52233-97e9-499c-bd82-2191ee6a2c55)


**Các thành phần chính:**

🔑 Quản Lý Khóa RSA: Tạo và tải khóa RSA (riêng tư của người nhận, công khai của người gửi).

▶️ Khởi Động Server: Nhập cổng và điều khiển việc bắt đầu/dừng máy chủ nhận.

📜 Nhật Ký Hoạt Động: Hiển thị chi tiết quá trình nhận, xác minh, giải mã file.

**Công cụ xác minh Offline (verify_tool.py)**
![image](https://github.com/user-attachments/assets/01b07377-7788-4f85-a463-76c3c4da9fb5)


Công cụ dòng lệnh này cho phép xác minh tính toàn vẹn và xác thực của một phần file đã nhận một cách độc lập, bằng cách cung cấp khóa công khai của người gửi, Hash (Base64) và Chữ ký (Base64) từ log.

## 🚀 **Hướng dẫn cài đặt và chạy chi tiết**


Để chạy dự án này, bạn cần đảm bảo môi trường Python đã được thiết lập và các thư viện cần thiết đã được cài đặt.

**Bước 1: Chuẩn bị môi trường**


Cài đặt Python: Đảm bảo bạn đã cài đặt Python 3.13.5 (hoặc phiên bản 3.x tương thích) trên hệ thống của mình. Bạn có thể tải xuống từ trang web chính thức của Python: python.org.

Clone Repository: Mở Terminal (trên Linux/macOS) hoặc PowerShell/Command Prompt (trên Windows) và thực hiện lệnh sau để tải dự án về máy tính của bạn:

**⬇️ git clone <địa chỉ repository của bạn>**

(Thay <địa chỉ repository của bạn> bằng URL kho GitHub của bạn.)

Di chuyển vào thư mục dự án:

**📁 cd <tên_thư_mục_dự_án_của_bạn>**

(Ví dụ: cd he_thong_truyen_file_an_toan)

**Bước 2: Thiết lập môi trường ảo**


Việc sử dụng môi trường ảo (virtual environment) là rất quan trọng để quản lý các thư viện Python của dự án một cách độc lập, tránh xung đột với các dự án khác.

**Tạo môi trường ảo:**

**📦 python -m venv myenv**

Lệnh này sẽ tạo một thư mục có tên myenv (hoặc tên bất kỳ bạn muốn) chứa môi trường ảo.

**Kích hoạt môi trường ảo:**

**Trên Windows (PowerShell):**

✅.\myenv\Scripts\activate

**Trên Windows (Command Prompt):**

✅myenv\Scripts\activate.bat

**Trên Linux/macOS:**

✅source myenv/bin/activate*

Khi môi trường ảo được kích hoạt, bạn sẽ thấy (myenv) (hoặc tên môi trường ảo của bạn) xuất hiện ở đầu dòng lệnh.

**Bước 3: Cài đặt các thư viện cần thiết**


Sau khi môi trường ảo đã được kích hoạt, bạn cần cài đặt các thư viện Python mà dự án sử dụng:

**⬇️pip install Flask pycryptodome**

**Flask:** Framework web để xây dựng giao diện người dùng.

**pycryptodome:** Thư viện mật mã cung cấp các thuật toán RSA, Triple DES, SHA-512, v.v.

**Bước 4: Chạy ứng dụng**


Bạn cần chạy ứng dụng Người nhận (ReceiverApp) và Người gửi (SenderApp) trên hai cửa sổ terminal/PowerShell/Command Prompt riêng biệt.

**Chạy ứng dụng Người nhận (ReceiverApp):**

**•** Mở một cửa sổ terminal/PowerShell/Command Prompt MỚI.

**•** Di chuyển vào thư mục dự án của bạn (cd <tên_thư_mục_dự_án_của_bạn>).

**•** Kích hoạt môi trường ảo (như Bước 2).

**•** Chạy lệnh sau để khởi động ReceiverApp:

**▶️python receiver_app.py**

**•** Bạn sẽ thấy thông báo server đang chạy. Mở trình duyệt web của bạn và truy cập địa chỉ: http://127.0.0.1:5001 để xem giao diện ReceiverApp.

**Chạy ứng dụng Người gửi (SenderApp):**

**•** Mở một cửa sổ terminal/PowerShell/Command Prompt KHÁC (để chạy song song với ReceiverApp).

**•** Di chuyển vào thư mục dự án của bạn (cd <tên_thư_mục_dự_án_của_bạn>).

**•** Kích hoạt môi trường ảo (như Bước 2).

**•** Chạy lệnh sau để khởi động SenderApp:

**▶️python sender_app.py**

**•** Mở trình duyệt web của bạn và truy cập địa chỉ: http://127.0.0.1:5000 để xem giao diện SenderApp.

**Chạy công cụ xác minh Offline (verify_tool.py):**

**•** Nếu bạn muốn sử dụng công cụ xác minh độc lập, mở một cửa sổ terminal/PowerShell/Command Prompt KHÁC nữa.

**•** Di chuyển vào thư mục dự án của bạn.

**•** Kích hoạt môi trường ảo (như Bước 2).

**•** Chạy lệnh sau:

**🔍python verify_tool.py**

**•** Làm theo hướng dẫn trên màn hình để nhập các thông tin cần thiết (đường dẫn khóa công khai của người gửi, hash Base64 và chữ ký Base64 từ nhật ký hoạt động của SenderApp).

**Bước 5: Sử dụng ứng dụng**


Sau khi cả SenderApp và ReceiverApp đều đang chạy và bạn đã truy cập giao diện web của chúng:

**Trên ReceiverApp** (http://127.0.0.1:5001):

**•** Tạo hoặc tải lên "Khóa Riêng Tư Người Nhận" (receiver_private_key.pem).

**•** Tạo hoặc tải lên "Khóa Công Khai Người Gửi" (sender_public_key.pem).

**•** Nhập cổng server (ví dụ: 5001) và nhấn "Bắt Đầu Server".

**Trên SenderApp** (http://127.0.0.1:5000):

**•** Tạo hoặc tải lên "Khóa Riêng Tư Người Gửi" (sender_private_key.pem).

**•** Tạo hoặc tải lên "Khóa Công Khai Người Nhận" (receiver_public_key.pem).

**•** Nhập "Địa Chỉ Máy Nhận" (thường là 127.0.0.1) và "Cổng" (ví dụ: 5001) rồi nhấn "Kết Nối".

**•** Sau khi kết nối thành công, chọn một file hợp đồng (ví dụ: contract.txt trong thư mục dự án của bạn) và nhấn "Gửi Hợp Đồng".

**•** Quan sát "Nhật Ký Hoạt Động" trên cả hai ứng dụng để theo dõi quá trình. Đặc biệt, trên SenderApp, bạn sẽ thấy các chuỗi Hash (Base64) và Chữ ký (Base64) của từng phần file được hiển thị.

**Xác minh với verify_tool.py:**

**•** Sử dụng các chuỗi Hash (Base64) và Chữ ký (Base64) từ nhật ký của SenderApp.

**•** Chạy verify_tool.py và dán các chuỗi này cùng với đường dẫn đến sender_public_key.pem để xác minh độc lập.

Chúc bạn thành công với dự án của mình!
