# 15. Forensic Evidence Preservation (Bảo toàn tính toàn vẹn bằng chứng)

> **Quy tắc vàng của DFIR**: Bằng chứng gốc sau khi thu thập **tuyệt đối không bao giờ được phép chỉnh sửa**. Mọi hoạt động phân tích (chạy Volatility, quét YARA, trích xuất chuỗi ký tự) đều chỉ được thực hiện trên **bản sao làm việc (Forensic Working Copy)**.

---

## 1. Nguyên tắc 4 lớp Bảo toàn (4-Tier Preservation Standard)

```
       ENDPOINT CAPTURE ──► [1. HASH TỨC THÌ (SHA-256)]
                                     │
                                     ▼ Kênh truyền bảo mật (TLS)
       EVIDENCE INGEST  ──► [2. VERIFY HASH KHỚP 100%]
                                     │
                                     ▼
       OBJECT STORE     ──► [3. GHI VÀO VÙNG WORM (READ-ONLY)]
                                     │
                                     ▼
       ANALYSIS WORK    ──► [4. NHÂN BẢN FORENSIC WORKING COPY] ──► AI / Volatility
```

1. **Hash tức thì tại điểm thu thập (Capture-time Hashing)**:
   - Ngay khi công cụ kết thúc ghi file `memory.raw` hoặc trích xuất log trên PC1, tiến trình tự động tính mã băm SHA-256 / BLAKE3 ngay trên máy trạm trước khi gửi đi.
2. **Xác minh kép khi tiếp nhận (Ingest Verification)**:
   - Khi Server nhận xong file bằng chứng, Server tính toán lại mã hash độc lập. Nếu 2 mã băm trùng khớp tuyệt đối, bằng chứng được chấp nhận.
3. **Lưu trữ bất biến (WORM - Write Once, Read Many)**:
   - File được gắn cờ `Read-Only` ở cấp hệ thống file hoặc Object Lock (như MinIO / AWS S3 Object Lock).
   - Không người dùng hay tiến trình nào (kể cả AI) có quyền ghi đè hoặc xóa bỏ file bằng chứng gốc này.
4. **Phân tích trên bản sao (Forensic Working Copy)**:
   - Khi công cụ như Volatility 3 hay MCP cần đọc file `memory.raw`, hệ thống tạo một liên kết tạm (Snapshot Copy / Read-only Mount) để phân tích, đảm bảo file gốc hoàn toàn nguyên vẹn.
