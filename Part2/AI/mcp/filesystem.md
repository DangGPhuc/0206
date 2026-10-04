# 32. MCP Tool: Filesystem Forensics & NTFS Artifacts

> **Mục tiêu**: Cung cấp khả năng phân tích hệ thống file NTFS cho AI Investigator.  
> Giúp truy vết sự tồn tại của file, lịch sử tạo/xóa và vạch trần kỹ thuật ngụy tạo mốc thời gian file (**Timestomping**).

---

## 1. Các thành phần pháp y hệ thống file

| Thành phần | Đường dẫn / Cấu trúc | Ý nghĩa điều tra |
| :--- | :--- | :--- |
| **$MFT (Master File Table)** | File siêu dữ liệu ẩn `$MFT` tại gốc phân vùng NTFS | Lưu trữ toàn bộ thông tin về mọi file và thư mục trên ổ đĩa. Giúp phân tích 2 bộ thuộc tính thời gian: `$STANDARD_INFORMATION` (SI) và `$FILE_NAME` (FN). |
| **Phát hiện Timestomping** | So sánh mốc MACB giữa SI và FN | Kẻ tấn công dùng công cụ sửa thuộc tính `$STANDARD_INFORMATION` về năm 2020 để ngụy trang file hệ thống cũ. Tuy nhiên, thuộc tính `$FILE_NAME` do Windows Kernel kiểm soát chỉ ghi nhận thời gian thực (2026) ➔ Phát hiện ngụy tạo thời gian! |
| **Windows Prefetch** | `C:\Windows\Prefetch\*.pf` | Cung cấp bằng chứng thực thi không thể chối cãi: Số lần chạy, 8 mốc thời gian chạy gần nhất, và danh sách các DLL mà file đã nạp vào. |
| **Zone.Identifier (MOTW)** | Luồng dữ liệu thay thế (ADS) `:Zone.Identifier` | Chứng minh file được tải về từ Internet (`ZoneId=3`) kèm theo URL nguồn và URL giới thiệu của kẻ phát tán. |

---

## 2. Giao diện gọi hàm của MCP Filesystem Tool

```json
{
  "tool": "filesystem_inspect_file",
  "arguments": {
    "host": "PC1",
    "file_path": "C:\\Users\\Public\\evil.exe"
  }
}
```

### Kết quả trả về cho AI:
```json
{
  "status": "success",
  "file_metadata": {
    "file_name": "evil.exe",
    "size_bytes": 1048576,
    "hashes": {
      "sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    },
    "timestomping_detected": true,
    "timestamps": {
      "standard_information": {
        "created": "2021-04-12T08:00:00Z"
      },
      "file_name": {
        "created": "2026-10-02T10:03:22Z"
      }
    },
    "zone_identifier": {
      "zone_id": 3,
      "zone_name": "Internet",
      "host_url": "http://185.220.101.5/evil.exe"
    }
  }
}
```
*Ý nghĩa*: AI phát hiện ra `evil.exe` đã cố tình sửa ngày tạo thành 2021 để đánh lừa mắt thường, nhưng mốc $FILE_NAME vạch trần nó vừa được sinh ra lúc 10:03:22 ngày 02/10/2026 từ Internet.
