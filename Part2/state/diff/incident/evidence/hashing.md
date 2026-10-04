# 19. Cryptographic Hashing & Tamper Detection

> **Nguyên tắc cốt lõi**: Mã băm (Hash) là "dấu vân tay điện tử" duy nhất của bằng chứng số. Nếu một file bằng chứng 16GB bị thay đổi dù chỉ **duy nhất 1 bit**, toàn bộ mã băm sẽ thay đổi hoàn toàn (hiệu ứng Avalanche).

---

## 1. Chiến lược băm kép (Dual-Hashing Strategy)

Trong điều tra số hiện đại, hệ thống sử dụng kết hợp 2 giải thuật băm:
1. **SHA-256**: Tiêu chuẩn pháp lý toàn cầu (NIST FIPS 180-4) được chấp nhận tại mọi tòa án và quy trình điều tra an ninh mạng.
2. **BLAKE3**: Thuật toán băm cây nhị phân (tree-based hash) tốc độ cao gấp 6-12 lần SHA-256. Đặc biệt tối ưu khi cần băm các file dung lượng khổng lồ như RAM Dump (16GB - 64GB) hoặc file PCAP mạng nhiều Gigabyte trong vài giây ngay trên endpoint.

---

## 2. Quy trình kiểm tra tính toàn vẹn 3 bước (3-Point Verification)

```
 [1. TẠI ENDPOINT]                 [2. TẠI SERVER INGEST]             [3. TRƯỚC KHI BÁO CÁO / PHÂN TÍCH]
  Thu thập memory.raw               Nhận xong file                     AI/DFIR mở file phân tích
         │                                 │                                          │
         ▼                                 ▼                                          ▼
  Tính Hash ban đầu                 Tính lại Hash độc lập              Tính Hash kiểm tra lại
  H_origin = SHA256(...)            H_ingest = SHA256(...)             H_verify = SHA256(...)
         │                                 │                                          │
         └─────────────┬───────────────────┘                                          │
                       ▼                                                              ▼
               H_origin == H_ingest ?                                         H_verify == H_origin ?
                 ├── ĐÚNG ➔ Lưu vào WORM                                        ├── ĐÚNG ➔ Bằng chứng nguyên vẹn
                 └── SAI  ➔ BÁO ĐỘNG GIẢ MẠO!                                   └── SAI  ➔ TAMPER_DETECTED!
```

---

## 3. Nhật ký kiểm tra định kỳ (Integrity Scrubber)
- Định kỳ 24 giờ, tiến trình ngầm (Scrubber Daemon) tự động quét lại toàn bộ kho bằng chứng, băm lại các file và đối chiếu với giá trị trong `Manifest`.
- Nếu phát hiện bất kỳ file nào có hash sai lệch (do lỗi đĩa hoặc bị can thiệp trái phép), hệ thống lập tức khóa sự cố và gửi thông báo khẩn cấp tới chuyên gia DFIR.
