# 25. Hypothesis Engine (Analysis of Competing Hypotheses - ACH)

> **Vai trò**: Đóng vai trò là "Bộ khung chẩn đoán khoa học" của quá trình điều tra số.  
> Ngăn chặn việc AI hoặc con người bị thiên kiến xác nhận (Confirmation Bias) bằng cách thiết lập các giả thuyết cạnh tranh, liên tục kiểm chứng bằng bằng chứng thực tế và cập nhật trạng thái rõ ràng.

---

## 1. Vòng đời của một Giả thuyết điều tra (Hypothesis Lifecycle)

```
                            ┌────────────────────────┐
                            │    PROPOSED (Đề xuất)  │
                            │ "Giả thuyết: PC1 bị    │
                            │  nhiễm qua Word Macro" │
                            └───────────┬────────────┘
                                        │
                                        ▼ Thu thập bằng chứng
                            ┌────────────────────────┐
                            │  EVIDENCED (Có cơ sở)  │
                            │ Tìm thấy file Invoice  │
                            │ có macro trong Outlook │
                            └───────────┬────────────┘
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼ Đối chiếu bằng chứng sâu                    ▼ Có phản chứng rõ ràng
    ┌─────────────────────────┐                   ┌─────────────────────────┐
    │  CONFIRMED (Xác nhận)   │                   │   REFUTED (Bác bỏ)      │
    │ Sysmon ghi nhận PID     │                   │ Macro vô hại, người     │
    │ WINWORD trực tiếp tạo   │                   │ dùng tự mở PowerShell   │
    │ powershell.exe          │                   │ bằng tay hợp lệ         │
    └─────────────────────────┘                   └─────────────────────────┘
```

---

## 2. Bảng ma trận đối chiếu giả thuyết (Ví dụ Incident INC-001)

| Mã giả thuyết | Nội dung giả thuyết | Bằng chứng ủng hộ (Supporting) | Phản chứng (Refuting) | Trạng thái cuối cùng |
| :--- | :--- | :--- | :--- | :--- |
| **H1** | Kẻ tấn công khai thác lỗ hổng từ xa (RCE) trên Windows Print Spooler | Port 445 mở | Cây tiến trình không liên quan đến `spoolsv.exe`, không có crash dump | **REFUTED** |
| **H2** | Người dùng mở tài liệu Phishing kích hoạt PowerShell tải mã độc | Prefetch ghi nhận WINWORD, Sysmon Event 1 cho thấy Word tạo PowerShell, Suricata C2 alert | Không có | **CONFIRMED** |
| **H3** | Mã độc đã thiết lập cơ chế khởi động lại cùng Windows (Persistence) | Khóa Registry `HKCU\...\Run\Evil` trỏ đến `evil.exe`, Diff S2 vs S3 có khóa này | Không có | **CONFIRMED** |
| **H4** | Kẻ tấn công đã đánh cắp toàn bộ cơ sở dữ liệu khách hàng | Lưu lượng mạng có kết nối ra ngoài | Zeek thống kê tổng dung lượng tải lên chỉ có 14KB (chỉ là beacon C2, chưa có data exfiltration lớn) | **REFUTED** |

---

## 3. Lợi ích khi tích hợp với AI
- AI không đưa ra kết luận cảm tính hay suy đoán vô căn cứ.
- Mọi kết luận trong báo cáo cuối cùng đều phải gắn liền với một giả thuyết mang trạng thái **CONFIRMED** và có tham chiếu chính xác đến `Evidence ID`.