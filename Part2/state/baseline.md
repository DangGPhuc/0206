# 7. Known-Good Baseline & Multi-Point Comparison

> **Khái niệm then chốt**: **Baseline KHÔNG đơn giản là Snapshot liền kề trước đó (S2)**.  
> Nếu chỉ lấy S2 làm chuẩn, hệ thống sẽ rơi vào cái bẫy "kẻ tấn công đã xâm nhập từ trước đó" (Dwell Time). Nếu mã độc thâm nhập từ 09:55, thì Snapshot S2 lúc 10:00 đã bị nhiễm, việc so sánh S2 với S3 sẽ bỏ sót hoàn toàn dấu vết ban đầu.

---

## 1. Vấn đề của việc chỉ so sánh S2 vs S3

```
  09:00                   09:55              10:00 (S2)           10:05 (S3)
────┬───────────────────────┼───────────────────┼───────────────────┼────► TIME
    │                       │                   │                   │
  BASELINE              Attacker            Malware nằm         Malware chạy
(Sạch 100%)             thâm nhập           vùng vẫy ngầm       leo thang đặc quyền
```
- Nếu chỉ so `S2 vs S3`: Bạn chỉ thấy hành vi "leo thang đặc quyền" lúc 10:05, hoàn toàn mù mờ về việc mã độc đã nằm trên máy từ khi nào.
- Vì vậy, hệ thống bắt buộc phải duy trì **Bản chuẩn an toàn đã biết (LAST_KNOWN_GOOD_BASELINE)**.

---

## 2. Mô hình so sánh kép (Dual-Comparison Engine)

Khi phân tích sự cố tại S3, hệ thống chạy **hai phép so sánh độc lập**:

```
                       ┌────────────────────────────────┐
                       │          SNAPSHOT S3           │
                       │     (Trạng thái nghi ngờ)      │
                       └───────┬────────────────┬───────┘
                               │                │
            ┌──────────────────┘                └──────────────────┐
            ▼ Phép so sánh 1                                       ▼ Phép so sánh 2
   [ S2 vs S3 DIFF ]                                      [ BASELINE vs S3 DIFF ]
   ─────────────────                                      ───────────────────────
   Trả lời câu hỏi:                                       Trả lời câu hỏi:
   "5 phút qua có gì MỚI xuất hiện?"                     "Máy tính đã lệch khỏi chuẩn sạch
                                                          (golden state) bao nhiêu phần?"
   - Phát hiện payload vừa kích hoạt                      - Phát hiện backdoor cài từ tuần trước
   - Socket mạng mới mở                                   - Phát hiện user lạ mới tạo
   - File thực thi vừa rơi xuống đĩa                      - Phát hiện Defender đã bị vô hiệu hóa ngầm
```

---

## 3. Cách xác định và cập nhật LAST_KNOWN_GOOD_BASELINE

1. **Golden Baseline ban đầu**:
   - Được thiết lập khi máy tính vừa được cài đặt xong môi trường chuẩn (hoặc sau khi chuyên gia DFIR quét sạch hệ thống).
   - Chứa hash của toàn bộ file hệ thống, danh sách service chuẩn, autorun hợp lệ.
2. **Cơ chế cập nhật Baseline có kiểm soát (Baseline Promotion)**:
   - Một snapshot $S_k$ chỉ được thăng cấp (promote) thành Baseline mới khi và chỉ khi:
     - Đã trải qua $N$ chu kỳ liên tiếp không có bất kỳ cảnh báo bảo mật nào (Clean period).
     - Hoặc được xác nhận thủ công bởi quản trị viên / DFIR sau khi cập nhật phần mềm hợp lệ (Windows Update, cài đặt app có chữ ký số tin cậy).
