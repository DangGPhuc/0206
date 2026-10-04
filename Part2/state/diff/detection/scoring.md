# 12. Cumulative Risk Scoring & Alert Thresholds

> **Vai trò**: Chuyển đổi các phát hiện phân tích kỹ thuật thành **Điểm số rủi ro định lượng (Quantitative Risk Score)**.  
> Ngưỡng điểm này quyết định chính xác thời điểm hệ thống kích hoạt bảo toàn bằng chứng và đánh thức AI Triage, ngăn chặn báo động giả (False Positives) làm tràn ngập đội ngũ phân tích.

---

## 1. Bảng ma trận tính điểm rủi ro (Risk Scoring Matrix)

| Hành vi / Dấu hiệu phát hiện | Nguồn phát hiện | Điểm cơ bản | Ghi chú |
| :--- | :--- | :--- | :--- |
| **PowerShell khởi chạy bình thường** | Sysmon | **+10** | Hành vi phổ biến của admin |
| **Word / Excel gọi PowerShell** | Sigma | **+25** | Dấu hiệu Macro độc hại / Phishing |
| **PowerShell mã hóa chuỗi Base64 (-enc)** | Sigma | **+15** | Kỹ thuật che giấu mã lệnh |
| **Cảnh báo Suricata C2 (CobaltStrike / Metasploit)** | Suricata | **+35** | Chữ ký mã độc mạng mức độ nghiêm trọng |
| **File `.exe` mới được ghi vào đĩa (Diff S2 vs S3)** | State Diff | **+20** | Dropper tạo payload |
| **Tạo Registry Persistence (Run Key / Service)** | Sysmon / Diff | **+30** | Cơ chế khởi động lại cùng Windows |
| **Vô hiệu hóa Windows Defender / Security Log** | Sigma | **+40** | Cố tình xóa dấu vết / Evasion |
| **Kết nối mạng nội bộ bất thường (PC1 ➔ PC2:445)** | Zeek / Diff | **+25** | Dấu hiệu di chuyển ngang (Lateral Movement) |

---

## 2. Hệ số nhân theo chuỗi tương quan (Correlation Multiplier)

Nếu các sự kiện đứng rời rạc, điểm được cộng dồn đơn thuần. Nhưng nếu **Correlation Engine** xác nhận các sự kiện thuộc cùng một chuỗi nhân quả (Kill Chain):
- **Chuỗi có 2 mắt xích liên tiếp**: $\text{Score} = \text{Score} \times 1.2$
- **Chuỗi có 3 mắt xích liên tiếp**: $\text{Score} = \text{Score} \times 1.5$
- **Chuỗi có dấu hiệu di chuyển sang máy khác (Cross-host)**: Thêm ngay **+30 điểm** khẩn cấp.

---

## 3. Các phân tầng ngưỡng hành động (Threshold Action Tiers)

```
        0                               40                              70                            100+
        ├───────────────────────────────┼───────────────────────────────┼───────────────────────────────┤
                     LOW                            MEDIUM                           HIGH / CRITICAL
           [Ghi log bình thường]            [Tăng cường giám sát]              [KÍCH HOẠT SỰ CỐ KHẨN CẤP]
           - Không gọi AI                   - Đánh dấu máy cần theo dõi       1. Incident Manager tiếp nhận
           - Tiếp tục chu kỳ 5m             - Thu ngắn chu kỳ snapshot 1m     2. Freeze RAM & PCAP ngay
                                                                              3. Đánh thức AI Triage
```

### Chi tiết hành động tại từng ngưỡng:

1. **Điểm < 40 (LOW - Bình thường)**:
   - Dữ liệu tiếp tục được ghi vào Event Store và duy trì chu kỳ Snapshot 5 phút thông thường. Không gửi thông báo, không tốn tài nguyên.

2. **Điểm từ 40 đến 69 (MEDIUM - Đáng ngờ)**:
   - Hệ thống đưa PC vào diện theo dõi đặc biệt (Watchlist).
   - Tự động rút ngắn chu kỳ snapshot của riêng máy đó xuống 1 hoặc 2 phút để tăng độ phân giải quan sát.

3. **Điểm >= 70 (HIGH / CRITICAL - Sự cố bảo mật)**:
   - **Lập tức tạo Incident Ticket** trong hệ thống.
   - **Phát lệnh bảo quản tức thì (Volatile Freeze)**: Trích xuất RAM sống của PC1, lưu trữ file `.pcap` 15 phút gần nhất, thu thập cây tiến trình và socket.
   - **Đánh thức AI Triage Agent**: Bác sĩ cấp cứu AI được nạp toàn bộ gói dữ liệu tóm tắt để đánh giá và chuẩn bị hồ sơ cho DFIR.