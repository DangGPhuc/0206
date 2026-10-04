# 16. Deep Evidence Acquisition (Thu thập điều tra chuyên sâu)

> **Điều chỉnh định nghĩa quan trọng**:  
> **Không phải là "quay lại Velociraptor để trích xuất quá khứ tại S2"**, mà là:  
> **Kết hợp 3 nguồn bằng chứng độc lập**:
> 1. Trạng thái định kỳ đã lưu an toàn trên Server trước đó (`PC1_S2`, `PC1_S3`).
> 2. Trạng thái sâu ĐANG TỒN TẠI trên máy trạm NGAY BÂY GIỜ (Live Deep Triage).
> 3. Các dấu vết lịch sử được hệ điều hành Windows ghi nhận trên đĩa (Historical Forensic Artifacts: Prefetch, MFT, USN Journal, Amcache, EVTX).

---

## 1. Mô hình tam giác thu thập bằng chứng

```
                               ┌────────────────────────────────────────────────────────┐
                               │             TỔNG KHO DỮ LIỆU ĐIỀU TRA                  │
                               └───────────────────────────┬────────────────────────────┘
                                                           │
              ┌────────────────────────────────────────────┼────────────────────────────────────────────┐
              ▼                                            ▼                                            ▼
┌───────────────────────────┐                ┌───────────────────────────┐                ┌───────────────────────────┐
│ 1. SERVER STATE HISTORY   │                │ 2. LIVE CURRENT STATE     │                │ 3. HISTORICAL DISK RESIDUE│
│ (Đã lưu sẵn trên Server)  │                │ (Velociraptor thu NGAY)   │                │ (Dấu vết quá khứ còn lưu) │
├───────────────────────────┤                ├───────────────────────────┤                ├───────────────────────────┤
│ - PC1 @ Snapshot S2       │                │ - Toàn bộ RAM (memory.raw)│                │ - Prefetch (file đã chạy) │
│ - PC1 @ Snapshot S3       │                │ - Process memory dumps    │                │ - $MFT & $LogFile (NTFS)  │
│ - Events stream S2 ➔ S3   │                │ - Live network sockets    │                │ - USN Journal             │
│ - Suricata alerts         │                │ - File mã độc đang mở     │                │ - Amcache.hve & Shimcache │
│ - Zeek conn.log S2 ➔ S3   │                │ - Handles & DLLs loaded   │                │ - Windows Event Logs EVTX │
└───────────────────────────┘                └───────────────────────────┘                └───────────────────────────┘
```

---

## 2. Danh mục Artifacts trích xuất chuyên sâu (Deep Artifact Checklist)

Khi lệnh Deep Acquisition được kích hoạt, Velociraptor Server thực thi các artifact chuẩn:

1. **Bộ nhớ sống (Memory Artifacts)**:
   - `Windows.Memory.Acquisition` ➔ Thu thập toàn bộ file ảnh RAM (`memory.raw`) phục vụ phân tích bằng Volatility 3.
   - `Windows.Memory.ProcessDump` ➔ Dump bộ nhớ riêng của PID đáng ngờ (tiến trình `powershell.exe` và `evil.exe`).

2. **Dấu vết thực thi quá khứ (Evidence of Execution)**:
   - **Prefetch (`C:\Windows\Prefetch\*.pf`)**: Chứng minh các file `.exe` đã từng được chạy trong quá khứ kể cả khi file đó đã bị kẻ tấn công xóa khỏi đĩa.
   - **Amcache (`Amcache.hve`) & Shimcache**: Cung cấp đường dẫn file đầy đủ, kích thước, mã băm SHA1 và thời gian thực thi lần đầu.

3. **Dấu vết hệ thống file NTFS (Filesystem Residue)**:
   - **$MFT (Master File Table)**: Phân tích các thuộc tính `$STANDARD_INFORMATION` và `$FILE_NAME` để phát hiện kỹ thuật sửa đổi mốc thời gian file (**Timestomping**).
   - **USN Journal ($Extend\$UsnJrnl)**: Lịch sử mọi thao tác tạo, ghi, đổi tên và xóa file trên phân vùng ổ đĩa.

4. **Trích xuất File mẫu khả nghi (Sample Extraction)**:
   - Tự động bốc tách file `evil.exe`, các script PowerShell tạm (`.ps1`), file tài liệu Office độc hại (`Invoice.docm`) về kho lưu trữ an toàn để chạy YARA và phân tích mã độc tĩnh/động.