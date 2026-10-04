# 29. MCP Tool: Volatility 3 (Memory Forensics)

> **Mục tiêu**: Cung cấp cho AI Investigator khả năng mổ xẻ file ảnh bộ nhớ RAM sống (`memory.raw`) trích xuất từ PC1/PC2 tại thời điểm xảy ra sự cố.  
> Volatility 3 là công cụ pháp y bộ nhớ tiêu chuẩn vàng trong DFIR, giúp lật tẩy các kỹ thuật mã độc tinh vi chỉ tồn tại trong RAM (Fileless Malware).

---

## 1. Các Plugin hỗ trợ cho AI qua MCP

| MCP Tool Function | Plugin Volatility 3 tương ứng | Mục đích điều tra |
| :--- | :--- | :--- |
| `volatility_pslist` | `windows.pslist.PsList` | Liệt kê toàn bộ tiến trình có trong RAM; phát hiện tiến trình bị kẻ tấn công ẩn khỏi Task Manager (`psscan` / `pstree`). |
| `volatility_netscan` | `windows.netscan.NetScan` | Quét cấu trúc socket mạng trong kernel; tìm IP kết nối C2 và cổng nghe ngầm lúc capture RAM. |
| `volatility_malfind` | `windows.malfind.Malfind` | **Cực kỳ quan trọng**: Phát hiện kỹ thuật tiêm mã độc vào bộ nhớ (Process Injection / Process Hollowing). Tìm các vùng nhớ mang cờ `PAGE_EXECUTE_READWRITE` chứa shellcode hoặc header file PE (`MZ`). |
| `volatility_cmdline` | `windows.cmdline.CmdLine` | Trích xuất dòng lệnh thực tế của tiến trình còn lưu trong bộ nhớ đệm tiến trình (EPROCESS). |
| `volatility_dlllist` | `windows.dlllist.DllList` | Liệt kê các module DLL nạp vào không gian địa chỉ tiến trình, phát hiện DLL Side-Loading. |

---

## 2. Ví dụ AI gọi MCP Volatility & Kết quả trả về

### Yêu cầu từ AI:
```json
{
  "tool": "volatility_malfind",
  "arguments": {
    "evidence_id": "EVD-20261002-0042",
    "pid": 4820
  }
}
```

### Kết quả trả về cho AI:
```json
{
  "status": "success",
  "matches": [
    {
      "pid": 4820,
      "process_name": "powershell.exe",
      "start_vpn": "0x1a890000",
      "end_vpn": "0x1a892000",
      "protection": "PAGE_EXECUTE_READWRITE",
      "tag": "VadS",
      "hexdump_snippet": "4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|",
      "verdict": "Suspicious unmapped executable PE binary injected into powershell.exe address space"
    }
  ]
}
```
*Ý nghĩa*: AI ngay lập tức xác nhận có mã độc dạng nhị phân Windows PE đã được inject vào PowerShell, biến giả thuyết thành hiện thực.