# 26. Evidence Knowledge Graph (Đồ thị tri thức sự cố)

> **Vai trò**: Đóng vai trò là "Hồ sơ bệnh án tổng hợp" của toàn bộ cuộc tấn công dưới dạng đồ thị có hướng (Directed Graph).  
> Giúp liên kết mọi thực thể rời rạc (Tiến trình, File, Khóa Registry, Địa chỉ IP, Cổng mạng, Tài khoản) thành mạng lưới quan hệ nhân quả liền mạch và có thể truy vết ngược về từng bằng chứng cụ thể.

---

## 1. Cấu trúc Nút (Nodes) & Cạnh (Edges) trong Đồ thị

```
  [User: victim_user]
          │
          │ LOGGED_IN
          ▼
  [Process: WINWORD.EXE (PID: 3212)]
          │
          │ SPAWNED (Sysmon Event ID 1)
          ▼
  [Process: powershell.exe (PID: 4820)]
          │
          ├────────────── CONNECTED_TO (Zeek conn.log) ─────────────► [Remote IP: 185.220.101.5]
          │                                                                      │
          │ DROPPED (Sysmon Event ID 11)                                         │ SURICATA_ALERT
          ▼                                                                      ▼
  [File: C:\Users\Public\evil.exe] ◄── DOWNLOADED_FROM ──────────────────────────┘
          │
          ├────────────── MODIFIED (Sysmon Event ID 13) ────────────► [Registry: HKCU\...\Run\Evil]
          │
          │ SPAWNED / EXECUTED (Diff S2 vs S3)
          ▼
  [Process: evil.exe (PID: 5104)]
          │
          │ INJECTED_INTO (Volatility malfind EVD-0042)
          ▼
  [Memory: svchost.exe (PID: 892)]
          │
          │ LATERAL_SMB_CONNECT (Zeek / Event 4624)
          ▼
  [Host: PC2 (192.168.1.11)]
```

---

## 2. Định nghĩa các Thực thể & Mối quan hệ

### Các loại Nút (Node Types):
- `Host`: Định danh máy trạm (`PC1`, `PC2`).
- `User`: Tài khoản người dùng (`DOMAIN\victim_user`).
- `Process`: Thực thể tiến trình (`WINWORD.EXE`, `powershell.exe`).
- `File`: Đường dẫn tập tin trên đĩa (`Invoice.docm`, `evil.exe`).
- `RegistryKey`: Khóa đăng ký hệ thống (`HKCU\...\Run\Evil`).
- `NetworkEndpoint`: Địa chỉ IP & Cổng (`185.220.101.5:443`).
- `MemoryRegion`: Vùng nhớ khả nghi trong RAM (`PAGE_EXECUTE_READWRITE`).

### Các loại Cạnh quan hệ (Edge Types):
- `SPAWNED`: Tiến trình cha sinh ra tiến trình con.
- `DROPPED` / `CREATED`: Tiến trình ghi file mới xuống đĩa.
- `CONNECTED_TO`: Tiến trình mở kết nối mạng ra socket đích.
- `INJECTED_INTO`: Mã độc cấy luồng thực thi vào không gian bộ nhớ của tiến trình khác.
- `PERSISTED_VIA`: File được thiết lập tự chạy qua Registry hoặc Service.
- `ACCESSED_REMOTE`: Hành vi di chuyển ngang tác động lên máy khác.

---

## 3. Lợi ích khi AI và DFIR khai thác Đồ thị
1. **Xác định vùng ảnh hưởng (Blast Radius)**: Nhìn vào các nhánh của đồ thị để biết ngay lập tức có bao nhiêu máy trạm và tài khoản bị xâm nhập.
2. **Không bỏ sót mắt xích**: Nếu phát hiện tiến trình `evil.exe`, AI sẽ truy ngược theo cạnh `DROPPED` và `SPAWNED` để tìm ra kẻ đứng sau là `powershell.exe` và `WINWORD.EXE`.
3. **Minh bạch hóa phân tích**: Mỗi cạnh quan hệ đều đính kèm thuộc tính `evidence_id` và `timestamp`, cho phép nhấp chuột để mở file log gốc kiểm chứng.