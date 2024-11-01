# ddos_monitor
# Hệ Thống Phát Hiện và Ngăn Chặn Tấn Công DDoS

## Giới thiệu
Dự án này nhằm xây dựng một hệ thống tự động phát hiện và ngăn chặn tấn công từ chối dịch vụ phân tán (DDoS) sử dụng học máy. Hệ thống được thiết kế để giám sát lưu lượng mạng trên một máy chủ Ubuntu và áp dụng các mô hình học máy để phân loại các gói tin vào các loại tấn công DDoS hay không. Khi phát hiện tấn công, hệ thống sẽ thực hiện các biện pháp ngăn chặn thích hợp.

## Mục tiêu
- Phát hiện tấn công DDoS dựa trên phân tích lưu lượng mạng.
- Tự động ngăn chặn các tấn công DDoS khi phát hiện.
- Cung cấp một giải pháp an toàn cho các máy chủ trực tuyến, bảo vệ chúng khỏi những rủi ro tiềm tàng từ tấn công DDoS.

## Công nghệ Sử Dụng
- Python: Ngôn ngữ lập trình chính cho việc phát triển hệ thống.
- Scapy: Thư viện Python dùng để xử lý và phân tích gói tin mạng.
- Scikit-learn: Thư viện học máy được sử dụng để xây dựng và huấn luyện mô hình phát hiện DDoS.
- Pandas và Numpy: Thư viện hỗ trợ cho việc xử lý và phân tích dữ liệu.

## Cách Sử Dụng
1. **Cài đặt các thư viện cần thiết**:
   ```bash
   pip install scikit-learn pandas numpy scapy

# Datasets

## Dataset for DDoS Detection
You can download the dataset from the following link:

[Download Dataset](https://drive.google.com/file/d/1amqNCTs9boU6g9y57p8O2q7GeTIK35P9/view?usp=drive_link)
