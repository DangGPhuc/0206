# 8. Detection Engine (Deterministic Multi-Source Analytics)

> **Nguyên tắc then chốt**: **Detection Engine chạy hoàn toàn tự động, xác định (deterministic), không tốn token AI**.  
> Nó không chỉ phân tích sự thay đổi giữa 2 snapshot (diff), mà tiếp nhận **5 nguồn tín hiệu đồng thời** theo thời gian thực.  
> **Chỉ khi Risk Score vượt ngưỡng cảnh báo (Threshold)**, hệ thống mới đánh thức AI Triage.

---

## 1. Sơ đồ kiến trúc phát hiện đa nguồn (Multi-Source Detection)

```
   ┌───────────────────────────┐
   │    Snapshot State Diff    │ ──► [Cái gì mới xuất hiện / biến mất?]
   └─────────────┬─────────────┘
   ┌─────────────┴─────────────┐
   │   Sysmon Event Stream     │ ──► [Hành vi tiến trình, registry, DNS live]
   └─────────────┬─────────────┘
   ┌─────────────┴─────────────┐
   │    Suricata EVE Alerts    │ ──► [Chữ ký xâm nhập mạng tức thì (Realtime)]
   └─────────────┬─────────────┘          │
   ┌─────────────┴─────────────┐          ▼
   │      Zeek Metadata        │ ──► ┌────────────────────────────────────────┐
   └─────────────┬─────────────┘     │        DETECTION ENGINE CORE           │
   ┌─────────────┴─────────────┐     │                                        │
   │   Known-Good Baseline     │ ──► │  ├─ 1. Sigma Rules Matcher             │
   └───────────────────────────┘     │  ├─ 2. Anomaly Behavioral Detector     │
                                     │  ├─ 3. Multi-Stage Correlation Engine  │
                                     │  └─ 4. Cumulative Risk Scoring Matrix  │
                                     └────────────────────┬───────────────────┘
                                                          │
                                     ┌────────────────────┴───────────────────┐
                                     ▼                                        ▼
                            Risk Score < 70                          Risk Score >= 70
                           [BÌNH THƯỜNG / LƯU LOG]                   [BÁO ĐỘNG ĐỎ - HIGH ALERT]
                                     │                                        │
                                   Xong                                ┌──────┴───────────────┐
                                (Không gọi AI)                        │ 1. Kích hoạt Incident│
                                                                      │ 2. Đóng băng RAM/PCAP│
                                                                      │ 3. ĐÁNH THỨC AI TRIAGE│
                                                                      └──────────────────────┘
```

---

## 2. 5 Nguồn dữ liệu đầu vào của Detection

1. **State Diff (PC1@S2 vs PC1@S3)**:
   - Phát hiện các thực thể mới xuất hiện chưa từng có ở S2: tiến trình mới, dịch vụ mới, cổng mạng mới mở.
2. **Real-time Event Stream (Sysmon/EVTX)**:
   - Quan sát chuỗi hành vi liên tục diễn ra trong khoảng thời gian `(10:00, 10:05]`.
   - Ví dụ: `WINWORD.exe` sinh ra `powershell.exe`.
3. **Suricata Network Alerts**:
   - Cảnh báo ngay lập tức nếu có mã độc giao tiếp ra ngoài (C2, Exploit pattern) mà không cần đợi hết 5 phút để so sánh snapshot.
4. **Zeek Protocol Metrics**:
   - Lưu lượng bất thường: một máy trạm đột ngột truyền 2GB ra một địa chỉ IP nước ngoài qua cổng 443 không có chứng chỉ tin cậy.
5. **Baseline Drift**:
   - So sánh với `LAST_KNOWN_GOOD_BASELINE` để phát hiện các thay đổi âm thầm tích lũy theo thời gian.

---

## 3. Các module con bên trong Detection

- [sigma.md](file:///home/kali/Documents/0206/Part2/state/diff/detection/sigma.md): Bộ luật kiểm tra mẫu hành vi đã biết (Pattern matching).
- [anomaly.md](file:///home/kali/Documents/0206/Part2/state/diff/detection/anomaly.md): Phát hiện dị biệt bất thường theo ngữ cảnh (Contextual anomaly).
- [correlation.md](file:///home/kali/Documents/0206/Part2/state/diff/detection/correlation.md): Xâu chuỗi các sự kiện riêng lẻ thành chuỗi tấn công (Attack kill-chain).
- [scoring.md](file:///home/kali/Documents/0206/Part2/state/diff/detection/scoring.md): Tính điểm rủi ro tổng hợp và quyết định ngưỡng kích hoạt điều tra.
