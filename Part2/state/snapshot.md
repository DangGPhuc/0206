# 6. Periodic State Snapshots (Manifest & Checkpoints)

> **Nguyên tắc cốt lõi**: **EVENT ≠ SNAPSHOT**.  
> - **Event**: Là dòng chảy hành vi liên tục diễn ra theo thời gian thực (WINWORD khởi chạy, mở kết nối socket, tạo registry key...).  
> - **Snapshot**: Là bức ảnh tĩnh chụp trạng thái hệ điều hành tại một mốc thời gian cố định (mỗi 5 phút: S1 lúc 10:00, S2 lúc 10:05, S3 lúc 10:10...).

---

## 1. Bản chất của Snapshot trong hệ thống

Snapshot **không sao chép hàng triệu dòng log** vào bên trong. Snapshot thực chất là một **Bản kê trạng thái (State Manifest)** trỏ đến các ID trạng thái của từng máy trạm và mốc offset của dòng log mạng:

```
Snapshot S2 (10:00:00)                    Snapshot S3 (10:05:00)
┌────────────────────────────────┐        ┌────────────────────────────────┐
│ timestamp: 2026-10-02 10:00:00 │        │ timestamp: 2026-10-02 10:05:00 │
│ PC1 ──► state_id: pc1-state-S2 │        │ PC1 ──► state_id: pc1-state-S3 │
│ PC2 ──► state_id: pc2-state-S2 │        │ PC2 ──► state_id: pc2-state-S3 │
│ Network:                       │        │ Network:                       │
│   zeek_offset: 182991          │        │   zeek_offset: 184021          │
│   suricata_offset: 49102       │        │   suricata_offset: 49830       │
└────────────────────────────────┘        └────────────────────────────────┘
                 │                                        ▲
                 │        EVENTS XẢY RA GIỮA S2 VÀ S3    │
                 └────────────────────────────────────────┘
                    10:01 WINWORD.exe started
                    10:02 WINWORD → powershell.exe
                    10:03 powershell → 185.x.x.x
                    10:04 evil.exe created
```

---

## 2. Cấu trúc dữ liệu của Snapshot Manifest

```json
{
  "snapshot_id": "global_snap_20261002_100500",
  "snapshot_index": 3,
  "timestamp": "2026-10-02T10:05:00.000Z",
  "interval_seconds": 300,
  "endpoints": {
    "PC1": {
      "state_id": "pc1_state_S3_hash_9a8b",
      "status": "online",
      "metrics": {
        "process_count": 145,
        "socket_count": 31,
        "service_count": 89
      }
    },
    "PC2": {
      "state_id": "pc2_state_S3_hash_7c2d",
      "status": "online",
      "metrics": {
        "process_count": 112,
        "socket_count": 18,
        "service_count": 75
      }
    }
  },
  "network_sensor": {
    "zeek_stream_position": 184021,
    "suricata_alert_position": 49830,
    "pcap_active_ring_file": "ring_buffer_part_04.pcap"
  },
  "created_by": "system_scheduler_daemon"
}
```

---

## 3. Nội dung lưu bên trong từng State Checkpoint của Endpoint (`pc1_state_S3`)

Mỗi bản ghi trạng thái máy trạm (lấy qua Velociraptor hoặc Service) bao gồm:
1. **Process Table**: Toàn bộ tiến trình đang sống tại giây thứ `10:05:00` (PID, Name, Path, Commandline, Hash, ParentPID).
2. **Socket Table**: Mọi cổng mạng đang lắng nghe (Listening) hoặc kết nối thiết lập (ESTABLISHED).
3. **Autorun Keys**: Trạng thái hiện tại của các Registry Run keys, Scheduled Tasks, Startup Services.
4. **Active Users & Sessions**: Các phiên đăng nhập hiện tại trên máy.

---

## 4. Công thức điều tra Sự cố giữa 2 Snapshot (S2 → S3)

Khi phát hiện nghi vấn tấn công diễn ra trong khoảng thời gian từ `10:00` đến `10:05`, hệ thống không chỉ so sánh ảnh tĩnh của S2 và S3, mà kết hợp đầy đủ **ba thành phần**:

$$\text{Phân tích sự cố} = \text{Diff}(S_2, S_3) + \text{Events}(S_2 \to S_3) + \text{Network}(S_2 \to S_3)$$

1. **State Diff (Cái gì đã thay đổi?)**:
   - So sánh danh sách tiến trình giữa S2 và S3 ➔ Thấy xuất hiện thêm `powershell.exe` và `evil.exe`.
   - So sánh Registry giữa S2 và S3 ➔ Thấy xuất hiện khóa persistence `Run\Evil`.
2. **Event Stream (Tại sao và bằng cách nào nó thay đổi?)**:
   - Lọc các sự kiện Sysmon từ `10:00:00` đến `10:05:00` ➔ Thấy tiến trình `WINWORD.exe` đẻ ra `powershell.exe`, sau đó tải file `evil.exe` về máy.
3. **Network Stream (Các máy đã giao tiếp với ai?)**:
   - Zeek ghi nhận kết nối ra IP C2 `185.x.x.x`.
   - Zeek ghi nhận kết nối SMB từ PC1 sang PC2 lúc `10:04`.
