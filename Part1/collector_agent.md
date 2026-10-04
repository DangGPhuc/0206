# 1. Collector Agent (Endpoint Collection Subsystem)

> **Nguyên tắc cốt lõi**: **Collector Agent KHÔNG phải là AI Agent**.  
> Đây là một tiến trình/dịch vụ chạy ngầm cấp hệ điều hành (Windows Service / Linux Daemon), hoạt động độc lập, siêu nhẹ (lightweight), tiêu tốn cực ít tài nguyên CPU/RAM, không dùng token AI và không gọi LLM định kỳ.

---

## 1. Vai trò & Nhiệm vụ

Collector Agent chịu trách nhiệm thu thập thông tin trên từng máy trạm (PC1, PC2, ...) theo 2 cơ chế song song:

```
                      ┌──────────────────────────────────────────────┐
                      │             ENDPOINT (PC1 / PC2)             │
                      │                                              │
                      │  ┌──────────────┐      ┌──────────────────┐  │
                      │  │ Sysmon / ETW │      │ OS State Probers │  │
                      │  └──────┬───────┘      └────────┬─────────┘  │
                      │         │ Continuous            │ Every 5m   │
                      │         ▼                       ▼            │
                      │  ┌────────────────────────────────────────┐  │
                      │  │     COLLECTOR AGENT (Windows Service)  │  │
                      │  │                                        │  │
                      │  │  ├─ Event Watcher & Streaming          │  │
                      │  │  ├─ State Snapshot Prober              │  │
                      │  │  └─ Local Spooler (Offline Buffer)     │  │
                      │  └───────────────────┬────────────────────┘  │
                      └──────────────────────┼───────────────────────┘
                                             │ HTTPS / mTLS
                                             ▼
                                  DFIR SERVER (Ingest API)
```

1. **Continuous Event Streaming (Sự kiện thời gian thực liên tục)**:
   - Đọc trực tiếp từ Sysmon và Windows Event Log (ETW - Event Tracing for Windows).
   - Bắt ngay lập tức khi xảy ra:
     - Tạo/kết thúc tiến trình (`ProcessCreate` - Event ID 1, `ProcessTerminate` - Event ID 5).
     - Kết nối mạng từ tiến trình (`NetworkConnect` - Event ID 3).
     - Thay đổi Registry quan trọng (Run keys, Services, Winlogon - Event ID 12, 13, 14).
     - Truy vấn DNS (`DNSQuery` - Event ID 22).
     - Tạo file khả nghi (`FileCreate` - Event ID 11).

2. **Periodic State Collection (Lấy trạng thái định kỳ - Mặc định mỗi 5 phút)**:
   - Đến mỗi chu kỳ (ví dụ: 10:00, 10:05, 10:10):
     - Quét toàn bộ danh sách tiến trình đang chạy (`process_list`: PID, PPID, ImagePath, CommandLine, Hash, StartTime).
     - Quét danh sách Socket mạng đang mở (`sockets`: Protocol, LocalIP, LocalPort, RemoteIP, RemotePort, State, PID).
     - Quét danh sách Windows Services đang chạy (`services`: Name, Status, BinaryPath).
     - Quét cơ chế khởi động cùng hệ thống (`autoruns`: Run keys, Startup folders, Scheduled Tasks).
   - Đóng gói thành bản ghi trạng thái: `PC1_STATE_S<n>`.

3. **Local Spooler / Ring Buffer (Chống mất dữ liệu khi rớt mạng)**:
   - Nếu đường truyền tới Server bị ngắt, dữ liệu được ghi vào hàng đợi đệm cục bộ trên đĩa (Spool directory / SQLite / Rolling buffer).
   - Khi có mạng trở lại, Agent tự động đồng bộ bù (backfill/catch-up) theo đúng thứ tự thời gian.

---

## 2. Chiến lược triển khai (MVP vs Long-term)

| Giai đoạn | Giải pháp triển khai | Ưu điểm |
| :--- | :--- | :--- |
| **MVP (Khuyến nghị)** | **Sysmon + Velociraptor Client** | Không phải tự viết lại agent từ con số 0. Velociraptor Client đã có sẵn cơ chế Windows Service, VQL continuous monitoring (`CLIENT_EVENT`), buffer offline, mã hóa mTLS về Server và khả năng thu thập cực sâu khi có sự cố. |
| **Production / Tương lai** | **Custom Agent (Go / Rust)** | Tự viết agent chuyên dụng nếu muốn kiểm soát 100% tài nguyên, nhúng thêm cơ chế tự bảo vệ (Anti-tamper), heartbeat chuyên biệt hoặc tối ưu băng thông mạng nội bộ. |

---

## 3. Kiến trúc luồng dữ liệu (Data Flow)

```
[Sysmon / Event Log] ──► [Event Filter & Streamer] ──┐
                                                    ├──► [Local Spooler] ──► [Sender (TLS)] ──► Server Ingest
[Timer 5 phút]       ──► [State Collector Prober]  ──┘   (nếu mất mạng)
```

### Ví dụ dữ liệu Event liên tục (Continuous):
```json
{
  "timestamp": "2026-10-02T10:01:23.104Z",
  "host": "PC1",
  "source": "sysmon",
  "event_id": 1,
  "event_type": "process_create",
  "data": {
    "pid": 4820,
    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
    "parent_pid": 3212,
    "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "user": "DOMAIN\\victim_user",
    "hashes": "SHA256=A6B8F7..."
  }
}
```

### Ví dụ dữ liệu State định kỳ (Checkpoint 10:00 - Snapshot Component):
```json
{
  "state_id": "pc1-state-1000",
  "timestamp": "2026-10-02T10:00:00.000Z",
  "host": "PC1",
  "summary": {
    "process_count": 142,
    "socket_count": 28,
    "service_count": 89
  },
  "processes": [
    {"pid": 4, "name": "System"},
    {"pid": 892, "name": "svchost.exe"},
    {"pid": 3212, "name": "WINWORD.EXE"}
  ],
  "sockets": [
    {"local": "192.168.1.10:50412", "remote": "142.250.190.46:443", "pid": 3212}
  ],
  "autoruns": [
    {"location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "OneDrive", "path": "..."}
  ]
}
```