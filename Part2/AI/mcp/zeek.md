# 35. MCP Tool: Zeek & Network Log Analyzer

> **Mục tiêu**: Cung cấp cho AI Investigator khả năng tra cứu các giao dịch mạng chuyên sâu (Network Transactions) được Zeek ghi nhận trong cửa sổ sự cố giữa các Snapshot (ví dụ từ `10:00` đến `10:05`).

---

## 1. Các nguồn nhật ký mạng Zeek phục vụ điều tra

| Tên Log Zeek | Trường thông tin cốt lõi | Mục đích điều tra cho AI |
| :--- | :--- | :--- |
| `conn.log` | `ts`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `duration`, `orig_bytes`, `resp_bytes` | Xác định mọi phiên kết nối mạng, thời lượng phiên, dung lượng trao đổi (phát hiện rò rỉ dữ liệu hoặc beaconing). |
| `dns.log` | `ts`, `query`, `qtype_name`, `answers`, `rcode_name` | Truy vết các domain C2 độc hại, kỹ thuật DNS Tunneling hoặc DGA (Domain Generation Algorithm). |
| `http.log` | `ts`, `method`, `host`, `uri`, `user_agent`, `status_code` | Chi tiết các yêu cầu tải mã độc qua web, User-Agent bất thường. |
| `ssl.log` | `ts`, `server_name`, `ja3`, `ja3s`, `subject`, `issuer` | Nhận diện dấu vân tay mã hóa SSL/TLS của các công cụ tấn công (JA3/JA3S fingerprint). |
| `smb_files.log` | `ts`, `path`, `name`, `action` | Xác định chính xác file nào đã được sao chép qua chia sẻ mạng SMB giữa PC1 và PC2. |

---

## 2. Giao diện gọi hàm qua MCP

```json
{
  "tool": "zeek_query_connections",
  "arguments": {
    "source_ip": "192.168.1.10",
    "time_range": {
      "start": "2026-10-02T10:00:00Z",
      "end": "2026-10-02T10:05:00Z"
    },
    "filter_type": "external_only"
  }
}
```

### Kết quả trả về cho AI:
```json
{
  "status": "success",
  "connections": [
    {
      "timestamp": "2026-10-02T10:02:08.450Z",
      "dest_ip": "185.220.101.5",
      "dest_port": 443,
      "proto": "tcp",
      "duration_sec": 182.4,
      "orig_bytes": 4820,
      "resp_bytes": 1048576,
      "ja3": "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
      "verdict": "Long-lived encrypted session transferring ~1MB inbound (Payload download)"
    }
  ]
}
```
*Ý nghĩa*: AI xác nhận chính xác kết nối ra IP `185.220.101.5` đã kéo về đúng 1,048,576 bytes (trùng khớp với kích thước của `evil.exe`).
