# 14. Volatile Evidence Freezing (Đóng băng dữ liệu dễ bốc hơi)

> **Hiểu đúng về Freeze trong DFIR**:  
> **Hệ thống KHÔNG THỂ quay ngược thời gian để đóng băng RAM lúc S2 (10:00)** — vì RAM tại 10:00 đã bị ghi đè và biến mất vĩnh viễn! S2 đã được lưu an toàn trước đó dưới dạng bản ghi trạng thái (State Checkpoint).  
> **Freeze ở đây là**: Ngay khi Detection báo động tại thời điểm `10:05:03`, hệ thống lập tức chụp giữ trạng thái dễ bốc hơi **NGAY TẠI THỜI ĐIỂM HIỆN TẠI** trước khi kẻ tấn công kịp xóa dấu vết hoặc tắt máy.

---

## 1. Trật tự bốc hơi của bằng chứng số (Order of Volatility - RFC 3227)

Dữ liệu biến mất theo thứ tự thời gian, do đó hệ thống kích hoạt đóng băng theo thứ tự ưu tiên nghiêm ngặt:

```
Thứ tự ưu tiên      Loại dữ liệu cần đóng băng ngay lập tức
─────────────────────────────────────────────────────────────────────────────
1. Cao nhất (Vài giây)   ►  Bộ nhớ RAM sống (Physical Memory / Process Memory)
2. Cao (Vài phút)        ►  Danh sách kết nối mạng sống (Active TCP/UDP Sockets)
3. Cao (Vài phút)        ►  Bảng tiến trình đang chạy (Process Tree & Handles)
4. Trung bình            ►  Vùng đệm mạng thô (PCAP Rolling Ring Buffer)
5. Thấp hơn              ►  File tạm trong bộ nhớ đệm (%TEMP%, AppData, Prefetch)
6. Bền vững              ►  Windows Event Logs (EVTX), Registry Hives, $MFT
```

---

## 2. Kịch bản Đóng băng Thực tế (Timestamp Walkthrough)

- **10:05:00**: Snapshot S3 hoàn thành thu thập định kỳ (nhận diện tiến trình lạ `powershell.exe`, `evil.exe`).
- **10:05:03**: Detection Engine tính toán `Risk Score = 105 >= 70` ➔ Phát tín hiệu **HIGH ALERT**.
- **10:05:04 - Hành động Đóng băng Tức thì (Instant Freeze Execution)**:
  1. **Trên PC1 (Endpoint Freeze)**:
     - Gửi lệnh Velociraptor VQL khẩn cấp: Chụp toàn bộ bộ nhớ RAM của PC1 (`memory.raw`) hoặc dump riêng bộ nhớ của tiến trình khả nghi (PID 4820 - `powershell.exe`).
     - Dump snapshot bảng kết nối mạng socket (`netstat -ano`) và routing table.
     - Sao lưu thư mục file tạm thời nơi mã độc vừa thả file (`C:\Users\Public\evil.exe`).
  2. **Trên Network Sensor (Network Freeze)**:
     - Khóa đoạn file trong **PCAP Ring Buffer** bao trùm khoảng thời gian từ `10:00:00` đến `10:10:00` (đóng băng lưu lượng trước và sau khi mã độc kích hoạt).
     - Ngăn chặn vòng quay (ring rotation) ghi đè lên phân đoạn gói tin quan trọng này.
  3. **Trên Server**:
     - Đánh dấu trạng thái Snapshot S2 và S3 chuyển sang chế độ **READ-ONLY / LOCKED** (khóa chống sửa đổi).