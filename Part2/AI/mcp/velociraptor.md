# 34. MCP Tool: Velociraptor VQL Client Tasking

> **Mục tiêu**: Cung cấp giao diện an toàn cho AI Investigator tương tác với **Velociraptor Server**, cho phép gửi các truy vấn VQL (Velociraptor Query Language) có kiểm soát đến các máy trạm (PC1, PC2) để trích xuất artifact chuyên sâu mà không cần chạy lệnh shell tùy tiện.

---

## 1. Cơ chế ủy quyền an toàn (Delegated Tasking)

```
AI Investigator ──► MCP Gateway ──► Velociraptor Server ──► PC1 / PC2 Client
   (Yêu cầu VQL)    (Whitelist)       (mTLS Tasking)        (Thực thi cục bộ)
```
- **White-listed Artifacts**: AI chỉ được gọi các VQL Artifacts nằm trong danh mục cho phép (ví dụ: `Windows.System.TaskScheduler`, `Windows.Network.ArpCache`, `Windows.Detection.Amcache`).
- **No Direct Remote Code Execution**: AI không thể gửi các lệnh PowerShell hay Bash tự do; mọi thao tác đều là đọc dữ liệu có cấu trúc.

---

## 2. Giao diện gọi hàm qua MCP

```json
{
  "tool": "velociraptor_collect_artifact",
  "arguments": {
    "host": "PC2",
    "artifact_name": "Windows.System.TaskScheduler",
    "parameters": {
      "pathFilter": ".*Updater.*"
    }
  }
}
```

### Kết quả trả về cho AI:
```json
{
  "status": "success",
  "rows": [
    {
      "TaskName": "\\UpdaterService",
      "Action": "C:\\Windows\\Temp\\evil_lateral.exe",
      "Author": "DOMAIN\\Administrator",
      "Created": "2026-10-02T10:04:46Z",
      "State": "Ready"
    }
  ]
}
```
*Ý nghĩa*: AI xác nhận ngay trên PC2 kẻ tấn công đã tạo thành công một Scheduled Task độc hại tên là `UpdaterService` để duy trì quyền điều khiển từ xa.
