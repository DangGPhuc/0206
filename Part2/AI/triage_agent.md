# 23. AI Triage Agent (Phân loại & Đánh giá cấp cứu)

> **Vai trò**: Đóng vai trò như "Bác sĩ cấp cứu" tiếp nhận ca bệnh.  
> Nhiệm vụ chính là đọc gói tóm tắt ban đầu của sự cố do `Incident Manager` gửi sang, đưa ra kết luận phân loại (LOW, MEDIUM, HIGH, CRITICAL), lý giải ngắn gọn bản chất mối nguy và đề xuất hành động ngăn chặn khẩn cấp.

---

## 1. Đầu vào của AI Triage Agent (Input Payload)

Agent nhận một cấu trúc JSON cô đọng được trích xuất sẵn từ hệ thống:

```json
{
  "incident_id": "INC-20261002-001",
  "trigger_score": 105,
  "affected_hosts": ["PC1", "PC2"],
  "state_diff_summary": {
    "PC1": {
      "new_processes": ["powershell.exe (PID: 4820)", "evil.exe (PID: 5104)"],
      "terminated_processes": [],
      "new_registry_keys": ["HKCU\\...\\Run\\Evil -> C:\\Users\\Public\\evil.exe"],
      "new_listening_or_outbound": ["192.168.1.10:49812 -> 185.220.101.5:443"]
    },
    "PC2": {
      "new_connections": ["Inbound from PC1 (192.168.1.10) to Port 445 (SMB)"]
    }
  },
  "top_alerts": [
    {"source": "Sigma", "title": "Office App Spawning PowerShell", "level": "HIGH"},
    {"source": "Suricata", "title": "ET MALWARE Suspicious CobaltStrike C2", "level": "CRITICAL"}
  ],
  "event_window_count": 48
}
```

---

## 2. Đầu ra chuẩn hóa của AI Triage (Output Schema)

AI Triage trả về cấu trúc phân loại nhanh không quá 200 từ:

```json
{
  "triage_verdict": "CRITICAL",
  "confidence": 0.96,
  "primary_threat_category": "Phishing Delivery leading to C2 & Lateral Movement",
  "justification": "Tiến trình WINWORD trên PC1 khởi chạy ngầm PowerShell để tải về mã độc evil.exe, đồng thời thiết lập kết nối C2 tới IP độc hại 185.220.101.5. Kẻ tấn công đã tạo khóa Registry khởi động cùng hệ thống và đang thực hiện di chuyển ngang (Lateral Movement) sang PC2 qua cổng SMB 445.",
  "immediate_actions": [
    "Cách ly mạng (Network Quarantine) ngay lập tức đối với PC1 và PC2",
    "Khóa cổng SMB Port 445 giữa các máy trạm nội bộ",
    "Chặn địa chỉ IP 185.220.101.5 trên tường lửa biên"
  ],
  "recommend_deep_investigation": true
}
```

---

## 3. Đặc điểm kỹ thuật
- **Nhanh**: Phản hồi trong vòng $2 - 5$ giây.
- **Tiết kiệm**: Prompt được tối ưu ngắn gọn, chỉ tiêu tốn khoảng vài trăm token mỗi lần sự cố xảy ra.
- **An toàn**: Không can thiệp sửa đổi hệ thống, chỉ cung cấp khuyến nghị cho chuyên gia DFIR.