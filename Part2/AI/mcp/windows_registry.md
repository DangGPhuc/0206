# 31. MCP Tool: Windows Registry Forensics

> **Mục tiêu**: Cho phép AI Investigator phân tích các file cấu hình nhị phân Registry Hives (`NTUSER.DAT`, `SYSTEM`, `SOFTWARE`) trích xuất từ endpoint để điều tra cơ chế khởi động cùng hệ thống (Persistence) và bằng chứng thực thi trong quá khứ.

---

## 1. Các nhánh Registry và Artifacts pháp y then chốt

| Phân vùng Registry | Khóa / Cơ chế kiểm tra | Ý nghĩa điều tra |
| :--- | :--- | :--- |
| **Run & RunOnce** | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`<br>`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Nơi mã độc thường ghi đường dẫn để tự động kích hoạt mỗi khi người dùng đăng nhập. |
| **Services** | `SYSTEM\CurrentControlSet\Services` | Danh sách dịch vụ hệ thống; phát hiện service mới trỏ tới file mã độc (`ImagePath`). |
| **UserAssist** | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | Bằng chứng người dùng đã chạy ứng dụng qua giao diện GUI (Dữ liệu mã hóa ROT13: Tên file, số lần mở, thời gian mở lần cuối). |
| **Shimcache (AppCompatCache)** | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Danh sách file `.exe` đã từng tồn tại và thực thi trên máy, bao gồm cả các file đã bị kẻ tấn công xóa bỏ. |
| **IFEO Injection** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` | Kỹ thuật chiếm quyền điều khiển: Khi mở ứng dụng hợp lệ (ví dụ: `sethc.exe` - Sticky Keys), hệ thống bị chuyển hướng sang chạy `cmd.exe` hoặc backdoor. |

---

## 2. Giao diện gọi hàm của MCP Registry Tool

```json
{
  "tool": "registry_query_key",
  "arguments": {
    "evidence_id": "EVD-20261002-0050",
    "hive_type": "NTUSER",
    "key_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  }
}
```

### Kết quả trả về cho AI:
```json
{
  "status": "success",
  "values": [
    {
      "value_name": "OneDrive",
      "value_type": "REG_SZ",
      "data": "\"C:\\Users\\victim\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
      "is_baseline_present": true
    },
    {
      "value_name": "Evil",
      "value_type": "REG_SZ",
      "data": "C:\\Users\\Public\\evil.exe",
      "is_baseline_present": false,
      "flag": "SUSPICIOUS_NEW_AUTORUN"
    }
  ]
}
```
*Ý nghĩa*: AI ngay lập tức xác minh khóa `Evil` hoàn toàn mới xuất hiện và không hề có trong `LAST_KNOWN_GOOD_BASELINE`.
