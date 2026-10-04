# 20. Evidence Object Store (Kho lưu trữ vật lý bằng chứng)

> **Vai trò**: Tầng lưu trữ vật lý chịu tải cho các file bằng chứng có dung lượng từ vài Megabyte (EVTX, Registry) đến hàng chục Gigabyte (RAM Dump, Raw PCAP).  
> Đảm bảo tính sẵn sàng cao, hiệu năng đọc phục vụ phân tích điều tra và cơ chế khóa bất biến (Immutability).

---

## 1. Cấu trúc thư mục lưu trữ phân cấp (Directory Hierarchy)

```
/evidence-vault/
│
├── INC-20261002-001/                                ◄── Thư mục theo từng Incident ID
│   ├── manifest.json                                ◄── Manifest chứng thực toàn bộ vụ việc
│   ├── chain_of_custody.log                         ◄── Lịch sử truy cập và vòng đời
│   │
│   ├── volatile/                                    ◄── Dữ liệu dễ bốc hơi
│   │   ├── EVD-20261002-0042_PC1_memory.raw         (16 GB - chmod 0400 / WORM Locked)
│   │   └── EVD-20261002-0046_powershell_proc.dmp    (240 MB)
│   │
│   ├── network/                                     ◄── Dữ liệu mạng trích xuất
│   │   ├── EVD-20261002-0043_window_1000_1010.pcap  (256 MB)
│   │   └── EVD-20261002-0047_zeek_extracted_conn.log
│   │
│   ├── disk_artifacts/                              ◄── Dữ liệu trích xuất từ đĩa
│   │   ├── EVD-20261002-0048_PC1_Security.evtx
│   │   ├── EVD-20261002-0049_PC1_Sysmon.evtx
│   │   └── EVD-20261002-0050_PC1_SYSTEM_hive
│   │
│   └── quarantine/                                  ◄── Mẫu mã độc đã được cách ly
│       └── EVD-20261002-0044_evil.exe.bin           (Mã hóa XOR/AES để tránh AV quét nhầm)
```

---

## 2. Công nghệ triển khai (Implementation Choices)

| Cấp độ | Công nghệ | Cơ chế bảo vệ |
| :--- | :--- | :--- |
| **MVP (Nội bộ / Lab)** | **Thư mục cục bộ Linux / MinIO** | Phân quyền nghiêm ngặt `chmod 0400` (chỉ đọc), gán thuộc tính `chattr +i` (bất biến - immutable) trên Linux ext4/xfs, hoặc bật MinIO Object Lock. |
| **Enterprise / Cloud** | **S3 / Ceph Object Store** | Bật **WORM (Write Once, Read Many) Compliance Mode**, tự động ngăn chặn xóa sửa kể cả với quyền Root cho tới khi hết thời hạn điều tra (Retention period). |

---

## 3. Cơ chế cách ly mẫu mã độc (Sample Quarantine)
- Các file nhị phân thực thi độc hại (`.exe`, `.dll`, `.vbs`, `.ps1`) khi được đưa vào Object Store bắt buộc phải được:
  1. Đổi phần mở rộng thành `.quarantine` hoặc `.bin` để tránh vô tình click đúp chạy nhầm.
  2. Mã hóa nhẹ (XOR bằng key `0x5A` hoặc AES-GCM) để tránh việc phần mềm diệt virus trên chính DFIR Server tự động xóa mất file bằng chứng.