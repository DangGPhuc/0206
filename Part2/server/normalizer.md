# 4. Server Normalizer (ETL Schema Standardizer)

> **Cảnh báo quan trọng**: **Normalizer KHÔNG PHẢI là Summary Report và KHÔNG DÙNG AI**.  
> Normalizer chỉ làm đúng một việc: Chuyển đổi định dạng log đa dạng từ các nguồn (Sysmon, Zeek, Suricata, Velociraptor) về **một định dạng chung duy nhất (Common Event Schema)**.  
> Không suy luận, không tóm tắt, không gọi model AI. Báo cáo (Report) chỉ được tạo ở giai đoạn cuối cùng của quá trình điều tra.

---

## 1. Sơ đồ xử lý chuẩn hóa

```
 ┌─────────────────┐
 │ Sysmon XML/JSON ├───────┐
 └─────────────────┘       │
 ┌─────────────────┐       │
 │ Zeek TSV / JSON ├───────┼──► ┌───────────────────────────┐      ┌─────────────────┐
 └─────────────────┘       │    │     SERVER NORMALIZER     │ ───► │  COMMON FORMAT  │
 ┌─────────────────┐       │    │ (Rule-based field mapping)│      │  (Unified JSON) │
 │ Suricata EVE    ├───────┤    └───────────────────────────┘      └─────────────────┘
 └─────────────────┘       │
 ┌─────────────────┐       │
 │ Velociraptor VQL├───────┘
 └─────────────────┘
```

---

## 2. Chuẩn dữ liệu chung (Common Event Schema)

Mọi log sau khi qua Normalizer đều tuân theo cấu trúc JSON thống nhất:

```json
{
  "timestamp": "2026-10-02T10:01:23.104Z",
  "host": "PC1",
  "source": "sysmon",
  "category": "process",
  "action": "create",
  "severity": "info",
  "actor": {
    "user": "DOMAIN\\victim_user",
    "process": {
      "pid": 3212,
      "name": "WINWORD.EXE",
      "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
    }
  },
  "target": {
    "process": {
      "pid": 4820,
      "name": "powershell.exe",
      "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
      "hashes": {
        "sha256": "A6B8F7D024B1..."
      }
    },
    "file": null,
    "registry": null,
    "network": null
  },
  "raw_ref": "sysmon_evt_1092812"
}
```

---

## 3. Bảng ánh xạ các trường (Mapping Table)

| Trường chuẩn hóa | Sysmon (Windows) | Zeek (Network) | Suricata (Network IDS) | Velociraptor VQL |
| :--- | :--- | :--- | :--- | :--- |
| `timestamp` | `UtcTime` / `SystemTime` | `ts` | `timestamp` | `Timestamp` |
| `host` | Computer Name | Gán theo IP/Interface | Gán theo IP/Sensor | `FQDN` / `ClientId` |
| `action` | `EventId` (1=create, 3=connect) | Giao thức / State | Alert Action | Tên Artifact query |
| `src_ip` | `SourceIp` (Event 3) | `id.orig_h` | `src_ip` | `Netstat.SourceAddress` |
| `dst_ip` | `DestinationIp` (Event 3) | `id.resp_h` | `dest_ip` | `Netstat.DestAddress` |
| `src_port` | `SourcePort` | `id.orig_p` | `src_port` | `Netstat.SourcePort` |
| `dst_port` | `DestinationPort` | `id.resp_p` | `dest_port` | `Netstat.DestPort` |
| `process` | `Image` | N/A | N/A | `Name` / `Exe` |
| `parent_proc` | `ParentImage` | N/A | N/A | `ParentName` |
| `command_line` | `CommandLine` | N/A | N/A | `CommandLine` |
| `query_domain` | `QueryName` (Event 22) | `query` (dns.log) | `dns.query.name` | `DnsCache.Name` |

---

## 4. Lợi ích kiến trúc của việc chuẩn hóa
1. **Detection Engine chạy mượt mà**: Bộ luật Sigma và Anomaly Detection chỉ cần viết một lần cho trường chuẩn (`target.process.name`), không cần quan tâm log đến từ Sysmon, Velociraptor hay EDR khác.
2. **AI Investigator dễ tiêu hóa**: Khi AI phân tích, nó nhận một bảng sự kiện đồng nhất, không bị quá tải hay "hallucinate" vì định dạng hỗn độn của các công cụ khác nhau.
3. **Hiệu năng cao**: Chạy bằng code thuần túy (Go / Python / Rust), xử lý hàng chục nghìn event mỗi giây mà không tốn tài nguyên.