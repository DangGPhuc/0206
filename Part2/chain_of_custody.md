# 21. Chain of Custody (Chuỗi bảo quản bằng chứng pháp lý)

> **Định nghĩa chuẩn mực**: **Chain of Custody (CoC)** KHÔNG PHẢI chỉ là "server đã làm gì khi nghi ngờ".  
> **Chain of Custody là hồ sơ lịch sử vòng đời hoàn chỉnh, minh bạch và không thể chối cãi của TỪNG BẰNG CHỨNG SỐ**: Từ giây phút bắt đầu thu thập, ai thu thập, công cụ nào, chuyển giao qua ai, lưu ở đâu, tính hash lúc nào, ai đã tạo bản sao để phân tích, và kết luận báo cáo.

---

## 1. Mẫu hồ sơ vòng đời bằng chứng (Ví dụ thực tế Evidence EVD-20261002-0042)

```
[BẰNG CHỨNG: EVD-20261002-0042 - PC1_memory.raw]
────────────────────────────────────────────────────────────────────────────────────────
THỜI GIAN (UTC)        HÀNH ĐỘNG / VÒNG ĐỜI               TÁC NHÂN             TRẠNG THÁI / HASH / GHI CHÚ
────────────────────────────────────────────────────────────────────────────────────────
10:05:11.200           Khởi động lệnh capture RAM         Velociraptor Client  PID 4920 WinPmem Driver trên PC1
10:05:36.850           Hoàn tất ghi file memory.raw       Velociraptor Client  Dung lượng: 17,179,869,184 bytes
10:05:37.100           Sinh mã băm nguồn (Capture Hash)   Velociraptor Client  SHA256: e3b0c44298fc1c149af...
10:05:38.000           Bắt đầu truyền tải mã hóa          TLS 1.3 Transport    Gửi từ 192.168.1.10 tới DFIR Server
10:05:50.420           Nhận trọn vẹn tại Ingest Server    Server Ingest        Tính lại SHA256 -> Khớp 100%
10:06:01.000           Lưu vào Evidence Store & WORM Lock Server Vault         Đổi quyền chmod 0400, gán cờ bất biến
10:06:05.000           Ghi nhận vào Case Manifest         Incident Manager     Liên kết với Incident INC-20261002-001
10:08:14.500           Tạo bản sao tạm thời (Working Copy)MCP Volatility Svc   Mount read-only để quét pslist/malfind
10:09:30.120           Phát hiện injection tiến trình     AI Investigator      Phát hiện shellcode trong PID 4820
10:15:00.000           Hủy bản sao tạm sau phân tích      MCP Volatility Svc   File gốc bất biến không bị suy suyển
────────────────────────────────────────────────────────────────────────────────────────
KẾT LUẬN TÍNH TOÀN VẸN: Bằng chứng nguyên vẹn 100%, đủ giá trị pháp lý làm việc trước tòa.
```

---

## 2. Cấu trúc Bản ghi CoC (Audit Entry JSON)

Mỗi sự kiện tác động lên bằng chứng được append-only vào sổ cái kiểm toán:

```json
{
  "log_id": "coc_log_81928",
  "evidence_id": "EVD-20261002-0042",
  "incident_id": "INC-20261002-001",
  "timestamp": "2026-10-02T10:08:14.500Z",
  "action": "CREATE_WORKING_COPY",
  "actor": {
    "type": "automated_service",
    "name": "mcp_volatility_service",
    "authenticated_user": "svc_dfir_automation"
  },
  "source_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "destination": "/tmp/working_copies/EVD-0042_copy_vol.raw",
  "purpose": "Execution of windows.malfind plugin for injected code detection",
  "signature": "SIGN_RSA_4096_..."
}
```

---

## 3. Ý nghĩa đối với điều tra số
1. **Chống phủ nhận (Non-repudiation)**: Bất kỳ ai truy cập xem xét bằng chứng đều bị ghi lại danh tính và thời gian.
2. **Loại trừ nghi ngờ làm sai lệch bằng chứng**: Khẳng định kết quả tìm thấy mã độc trong RAM là do kẻ tấn công để lại trên máy nạn nhân, chứ không phải do công cụ điều tra vô tình ghi đè vào.