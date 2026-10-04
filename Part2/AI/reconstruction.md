# 27. Attack Reconstruction & DFIR Reporting

> **Vai trò**: Tầng tổng hợp sản phẩm cuối cùng của cuộc điều tra.  
> Chuyển đổi toàn bộ kết quả phân tích kỹ thuật, đồ thị bằng chứng và kết quả kiểm tra giả thuyết thành **Timeline chính xác đến từng mili-giây**, **Sơ đồ ma trận tấn công MITRE ATT&CK**, **Cây nguồn gốc bằng chứng (Evidence Lineage)** và **Báo cáo sự cố số (Incident Report)** cho chuyên gia DFIR.

---

## 1. Các trụ cột của quá trình Tái dựng (Reconstruction Pillars)

```
                            ┌────────────────────────────────────┐
                            │    TÁI DỰNG TOÀN DIỆN CUỘC TẤN CÔNG │
                            └─────────────────┬──────────────────┘
                                              │
         ┌──────────────────┬─────────────────┼──────────────────┬──────────────────┐
         ▼                  ▼                 ▼                  ▼                  ▼
    1. Timeline        2. Attack Graph   3. Findings        4. Lineage         5. DFIR Report
    (Dòng thời gian)   (MITRE ATT&CK)    (Các phát hiện)    (Nguồn gốc chứng)  (Báo cáo chung)
```

---

## 2. Chi tiết từng trụ cột

### A. Chronological Master Timeline (Dòng thời gian tổng thể đa máy trạm)
Tổng hợp mọi sự kiện từ PC1, PC2 và Network Sensor theo đúng trình tự thời gian tuyệt đối:
```
10:00:00.000 UTC - [PC1] SNAPSHOT S2 (Hệ thống sạch, WINWORD mở, không có tiến trình lạ)
10:01:14.230 UTC - [PC1] WINWORD.EXE sinh ra powershell.exe ngầm (Sysmon ID 1)
10:02:05.110 UTC - [NET] powershell.exe truy vấn DNS domain c2.evilnetwork.com (Zeek dns.log)
10:02:08.450 UTC - [NET] Cảnh báo kết nối ra IP 185.220.101.5:443 (Suricata Alert Severity 1)
10:03:22.010 UTC - [PC1] File C:\Users\Public\evil.exe được tạo (Sysmon ID 11)
10:03:55.780 UTC - [PC1] Khóa Registry Run\Evil được thiết lập (Sysmon ID 13)
10:04:30.900 UTC - [NET] PC1 mở kết nối SMB Port 445 sang PC2 (Zeek conn.log)
10:04:45.120 UTC - [PC2] Tài khoản Administrator đăng nhập mạng Logon Type 3 (Security EVTX 4624)
10:05:00.000 UTC - [SYS] SNAPSHOT S3 hoàn tất (Diff phát hiện evil.exe, powershell.exe, Registry)
10:05:03.000 UTC - [DET] Detection báo Risk Score = 105 >= 70 (Kích hoạt Incident & Freeze)
```

### B. Attack Graph (Ánh xạ Ma trận MITRE ATT&CK)
Phân loại các hành vi vào các giai đoạn tấn công chuẩn:
- **T1566.001 - Spearphishing Attachment**: File `Invoice.docm` gửi qua email.
- **T1059.001 - PowerShell Execution**: Thực thi script giải mã ngầm.
- **T1071.001 - Web Protocols (C2)**: Giao tiếp qua HTTPS cổng 443 đến `185.220.101.5`.
- **T1547.001 - Registry Run Keys / Startup Folder**: Thiết lập persistence.
- **T1021.002 - SMB/Windows Admin Shares**: Di chuyển ngang sang PC2.

### C. Evidence Lineage (Cây phả hệ chứng cứ)
Mọi kết luận trong báo cáo đều phải chứng minh được nguồn gốc:
$$\text{Kết luận (Finding)} \longrightarrow \text{Mã băm bằng chứng (Evidence ID)} \longrightarrow \text{Dòng log gốc (Raw Event)}$$
- *Ví dụ*: Kết luận "Kẻ tấn công cấy mã vào RAM" ➔ trích dẫn `EVD-0042 (PC1_memory.raw)` ➔ SHA-256: `e3b0c442...` ➔ Volatility plugin: `windows.malfind` dòng `0x1a0000`.

### D. Final DFIR Incident Report (Cấu trúc Báo cáo Sự cố)
1. **Executive Summary (Dành cho Lãnh đạo)**: Tóm tắt mức độ thiệt hại, thời gian diễn ra, các máy bị ảnh hưởng, tình trạng cô lập hiện tại.
2. **Technical Details (Dành cho Kỹ thuật)**: Chi tiết mã độc, chỉ số IOCs (IP, Domain, File Hashes), sơ đồ phả hệ tiến trình.
3. **Root Cause Analysis (Nguyên nhân gốc rễ)**: Lỗ hổng hoặc thói quen của người dùng dẫn đến việc bị xâm nhập ban đầu.
4. **Remediation & Hardening (Khuyến nghị khắc phục)**: Các bước xóa bỏ mã độc, thu hồi tài khoản bị lộ, cấu hình lại tường lửa và cập nhật rule phòng thủ.
