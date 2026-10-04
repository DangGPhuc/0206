# 10. Behavioral & Contextual Anomaly Detection

> **Định nghĩa**: **Anomaly Detection** bổ sung cho Sigma Rules bằng cách tìm kiếm những hành vi **bất thường so với lịch sử hoạt động thông thường (Baseline Profile)** của từng máy trạm và người dùng, ngay cả khi hành vi đó không vi phạm trực tiếp một rule chữ ký cụ thể nào.

---

## 1. Các chiều phân tích bất thường (Anomaly Dimensions)

```
                              ┌──────────────────────────────────┐
                              │     ANOMALY DETECTION ENGINE     │
                              └─────────────────┬────────────────┘
                                                │
         ┌──────────────────┬───────────────────┼──────────────────┬──────────────────┐
         ▼                  ▼                   ▼                  ▼                  ▼
    1. Temporal        2. Process           3. Network         4. Volume         5. Account
    (Thời gian lạ)     (Cây tiến trình lạ)  (Kết nối lạ)       (Lượng log đột biến)(Phiên lạ)
```

---

## 2. Chi tiết các trường hợp phát hiện bất thường

### 1. Bất thường về thời gian hoạt động (Temporal Anomaly)
- **Hành vi**: Máy kế toán PC1 bình thường chỉ hoạt động từ 08:00 đến 17:30 các ngày trong tuần.
- **Dị biệt**: Lúc `03:15 AM`, xuất hiện tiến trình PowerShell thực thi các lệnh hệ thống.
- **Đánh giá**: Rủi ro cao vì nằm ngoài khung giờ làm việc của nhân viên (Off-hours execution).

### 2. Bất thường về phả hệ tiến trình (Process Lineage Anomaly)
- **Hành vi thông thường**: `spoolsv.exe` (Print Spooler) chỉ gọi các DLL in ấn.
- **Dị biệt**: `spoolsv.exe` sinh ra tiến trình con `cmd.exe` hoặc `powershell.exe` (Dấu hiệu đặc trưng của lỗ hổng PrintNightmare).

### 3. Bất thường về kết nối mạng & Tín hiệu Beaconing (Network Anomaly)
- **Tần suất đều đặn (Beaconing)**: Một tiến trình gửi gói tin HTTPS ra cùng một IP lạ với chu kỳ cố định (ví dụ: cứ 30 giây một lần với sai số jitter 5%).
- **Tên miền hiếm gặp (Rare Domain / Newly Registered Domain)**: Máy trạm truy vấn một domain được tạo cách đây 2 ngày và chưa từng được truy vấn trong toàn bộ mạng LAN.

### 4. Đột biến lưu lượng dữ liệu (Data Exfiltration Anomaly)
- **Lưu lượng Zeek**: Một máy trạm nội bộ bình thường tải lên trung bình 20MB/ngày đột ngột đẩy ra ngoài Internet 1.8GB chỉ trong 5 phút giữa S2 và S3.

### 5. Dấu hiệu nghi ngờ di chuyển ngang (Internal Lateral Anomaly)
- **Kết nối nội bộ lạ**: PC1 (phòng Nhân sự) đột ngột thiết lập phiên SMB/RPC (Port 445/135) đến PC2 (máy Kỹ thuật) - cặp giao tiếp này chưa từng xuất hiện trong lịch sử mạng.