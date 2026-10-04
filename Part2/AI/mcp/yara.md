# 33. MCP Tool: YARA Scanner & Rule Generator

> **Mục tiêu**: Cung cấp khả năng nhận diện họ mã độc (Malware Family Fingerprinting) cho AI Investigator thông qua tập luật nhận dạng YARA.  
> Hỗ trợ 2 chiều: Quét kiểm tra file nghi vấn và tự động sinh luật YARA để truy quét trên các máy khác.

---

## 1. Hai cơ chế hoạt động của YARA MCP Tool

```
  ┌────────────────────────────────────────────────────────┐
  │                   YARA MCP SERVICE                     │
  └───────────────────────────┬────────────────────────────┘
                              │
         ┌────────────────────┴────────────────────┐
         ▼                                         ▼
  1. YARA SCANNER                           2. YARA RULE GENERATOR
  (Quét đối chiếu tập luật có sẵn)          (AI tự sinh rule săn tìm)
  - Quét mẫu file: evil.exe                 - Trích xuất chuỗi độc nhất trong RAM
  - Quét memory.raw hoặc process dump       - Sinh file .yar chuẩn
  - Đối chiếu với kho Signature APT/C2      - Đẩy sang Velociraptor để Hunt
```

---

## 2. Ví dụ Quy tắc YARA và Kết quả quét qua MCP

### Tập luật YARA mẫu (CobaltStrike Beacon Identifier):
```yara
rule Suspicious_CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike Beacon in memory or dropped file"
        author = "DFIR Automation Team"
        severity = "CRITICAL"
    strings:
        $beacon_str1 = "%s as %s\\%s: %d" ascii
        $beacon_str2 = "Started service %s on %s" ascii
        $c2_pipe     = "\\\\.\\pipe\\msagent_" ascii
        $hex_config  = { 69 68 67 66 65 64 63 62 }
    condition:
        uint16(0) == 0x5A4D and (2 of ($beacon_str*) or $c2_pipe or $hex_config)
}
```

### Kết quả AI nhận được khi quét `evil.exe`:
```json
{
  "tool": "yara_scan_file",
  "status": "match_found",
  "matched_rules": [
    {
      "rule_name": "Suspicious_CobaltStrike_Beacon",
      "severity": "CRITICAL",
      "matched_strings": [
        {"identifier": "$beacon_str1", "offset": "0x0001f420"},
        {"identifier": "$c2_pipe", "offset": "0x00021a80"}
      ],
      "verdict": "Confirmed Cobalt Strike Beacon payload"
    }
  ]
}
```
*Ý nghĩa*: AI khẳng định chắc chắn 100% mẫu `evil.exe` chính là mã độc Cobalt Strike Beacon, một công cụ tấn công nguy hiểm thường được dùng trong các chiến dịch APT có chủ đích.
