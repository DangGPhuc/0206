# 3. Server Ingest & Event Store

> **Nguyên tắc thiết kế**: Tách biệt rõ ràng khái niệm giữa **Ingest (Cửa nhận hàng)** và **Event Store (Kho lưu trữ)**.  
> Trong giai đoạn MVP, cả hai có thể chạy chung trong một tiến trình (`server-core`), nhưng mã nguồn và tầng kiến trúc phải độc lập để dễ dàng mở rộng khi hệ thống lên tới hàng trăm hoặc hàng nghìn máy trạm.

---

## 1. Sơ đồ kiến trúc tầng Server

```
   Endpoints (PC1, PC2) & Network Sensors
             │                 │
             ▼ HTTPS / mTLS    ▼ Syslog / API
      ┌───────────────────────────────┐
      │         INGEST GATEWAY        │
      │   (Xác thực, Kiểm tra định dạng)│
      └──────────────┬────────────────┘
                     │ Raw Message Stream
                     ▼
      ┌───────────────────────────────┐
      │          NORMALIZER           │ ◄── Chuẩn hóa sang Common Event Schema
      └──────────────┬────────────────┘
                     │ Normalized Event Stream
                     ▼
      ┌───────────────────────────────┐
      │          EVENT STORE          │
      │                               │
      │  ├─ Time-series Events        │ (Sysmon, Zeek, Suricata)
      │  ├─ State Checkpoints         │ (PC1_State_S2, PC2_State_S2)
      │  └─ Fast Temporal Indexing    │ (Query theo khoảng thời gian [S2, S3])
      └──────────────┬────────────────┘
                     │ Query API
                     ▼
          Detection Engine & AI MCP
```

---

## 2. Ingest (Cửa nhận hàng)

### Nhiệm vụ:
1. **Xác thực và phân quyền (Authentication & mTLS)**:
   - Đảm bảo chỉ có các Agent và Sensor hợp lệ mới được đẩy dữ liệu vào Server.
   - Ngăn chặn kẻ tấn công giả mạo log hoặc gửi dữ liệu rác làm tràn ngập hệ thống.
2. **Buffer & Backpressure Control**:
   - Tiếp nhận luồng dữ liệu dồn dập từ nhiều máy cùng lúc mà không làm treo hệ thống.
   - Sử dụng hàng đợi trong bộ nhớ (In-memory queue / Channels / Redis / Kafka tùy quy mô).
3. **Chuyển tiếp thô**:
   - Đưa dữ liệu sang module `Normalizer` để chuẩn hóa trước khi ghi vào kho.

---

## 3. Event Store (Kho hàng thời gian thực)

### Nhiệm vụ:
1. **Lưu trữ dữ liệu có cấu trúc thời gian (Time-Series Partitioning)**:
   - Tối ưu hóa cho truy vấn theo dải thời gian: `timestamp >= S2 AND timestamp <= S3`.
   - Phân vùng theo ngày/giờ và theo định danh máy (`host_id`).
2. **Lưu trữ 2 phân vùng dữ liệu khác biệt**:
   - **Bảng Continuous Events**: Chứa hàng triệu bản ghi hành vi chi tiết (Sysmon, Zeek, Suricata).
   - **Bảng State Checkpoints**: Chứa các bức tranh trạng thái chụp tĩnh mỗi 5 phút (Process Table, Port/Socket Table, Autorun Table).
3. **Hỗ trợ truy vấn lát cắt sự cố (Incident Window Query)**:
   - Khi có nghi vấn tấn công giữa S2 (10:00) và S3 (10:05), Event Store cung cấp API truy vấn tức thì:
   ```sql
   SELECT * FROM normalized_events 
   WHERE host = 'PC1' 
     AND timestamp > '2026-10-02T10:00:00Z' 
     AND timestamp <= '2026-10-02T10:05:00Z'
   ORDER BY timestamp ASC;
   ```
4. **Lựa chọn công nghệ cho MVP vs Production**:
   - **MVP**: SQLite (WAL mode) hoặc DuckDB / PostgreSQL đơn node.
   - **Production**: ClickHouse hoặc Elasticsearch / OpenSearch chuyên dụng cho Big Data Log & Security Analytics.