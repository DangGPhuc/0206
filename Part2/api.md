# 5. Server API & MCP Gateway

> **Nguyên tắc cốt lõi**: **AI tuyệt đối KHÔNG được kết nối SSH/PowerShell trực tiếp vào PC1 hay PC2**.  
> Mọi tương tác của AI (Agentic LLM) hay chuyên gia bảo mật đều phải đi qua **MCP Gateway** và **Server API**, sau đó Server mới chuyển tiếp qua các hệ thống điều hành tập trung (như Velociraptor Server). Mô hình này đảm bảo an toàn, bảo vệ bằng chứng nguyên vẹn và ghi lại đầy đủ vết kiểm toán (Audit Trail).

---

## 1. Sơ đồ phân tầng kết nối

```
                        ┌───────────────────────────────┐
                        │      AI INVESTIGATOR / DFIR   │
                        └──────────────┬────────────────┘
                                       │ Tool Calls
                                       ▼
                        ┌───────────────────────────────┐
                        │          MCP GATEWAY          │
                        │    (Kiểm soát quyền & Audit)  │
                        └───────┬──────────────┬────────┘
                                │              │
            ┌───────────────────┘              └──────────────────┐
            ▼                                                     ▼
┌───────────────────────────────┐                 ┌───────────────────────────────┐
│        DFIR SERVER API        │                 │      VELOCIRAPTOR SERVER      │
│                               │                 │                               │
│  ├─ /api/v1/snapshots         │                 │  ├─ VQL Hunt Execution        │
│  ├─ /api/v1/events?from=&to=  │                 │  ├─ Deep Artifact Collection  │
│  ├─ /api/v1/evidence/download │                 │  └─ Memory Dump Trigger       │
│  └─ /api/v1/incidents/create  │                 └──────────────┬────────────────┘
└──────────────┬────────────────┘                                │
               │                                                 │ mTLS VQL Tasking
               │                                                 ▼
      Evidence Storage & DB                       ┌──────────────────────────────┐
                                                  │       PC1 / PC2 CLIENT       │
                                                  │   (Velociraptor Windows Svc) │
                                                  └──────────────────────────────┘
```

---

## 2. Các nhóm API chính của DFIR Server

### A. Endpoint Ingest API (Dành cho Agent/Sensors)
- `POST /api/v1/ingest/events`: Nhận streaming sự kiện liên tục từ Sysmon/Zeek/Suricata.
- `POST /api/v1/ingest/state`: Nhận gói trạng thái định kỳ 5 phút (`PC1_STATE_S2`, `PC2_STATE_S2`).
- `POST /api/v1/ingest/evidence`: Tải lên các file bằng chứng thô (RAM dump, EVTX, PCAP slice) kèm chữ ký hash.

### B. State & Query API (Dành cho Detection & Investigation)
- `GET /api/v1/snapshots`: Lấy danh sách các mốc Snapshot đã tạo (`S1`, `S2`, `S3`, ...).
- `GET /api/v1/snapshots/{id}/state?host=PC1`: Xem trạng thái hệ thống tại một mốc cụ thể.
- `GET /api/v1/diff?from=S2&to=S3&host=PC1`: Lấy kết quả sai khác trạng thái giữa hai mốc (Diff engine).
- `GET /api/v1/events/window?start=10:00:00&end=10:05:00&host=PC1`: Trích xuất toàn bộ luồng sự kiện xảy ra giữa hai mốc.

### C. Incident & Evidence API
- `POST /api/v1/incidents`: Khởi tạo sự cố mới khi điểm rủi ro vượt ngưỡng.
- `POST /api/v1/incidents/{id}/freeze`: Phát lệnh đóng băng bằng chứng dễ bốc hơi ngay lập tức.
- `GET /api/v1/evidence/{evidence_id}/manifest`: Lấy manifest và thông tin chuỗi bảo quản (Chain of Custody).

---

## 3. Vai trò của MCP Gateway đối với AI

Khi AI Investigator muốn điều tra sâu, nó gọi các MCP Tools tương ứng:
1. AI gọi tool `query_events_window(host="PC1", from="10:00", to="10:05")` ➔ MCP Gateway chuyển tiếp gọi Server API ➔ trả về danh sách event chuẩn hóa.
2. AI gọi tool `velociraptor_collect_mft(host="PC1")` ➔ MCP Gateway gọi Velociraptor API ➔ Velociraptor Server ra lệnh cho PC1 thu thập `$MFT` và trả về kết quả cho AI.
3. Toàn bộ thao tác của AI đều được ký số và ghi nhật ký kiểm toán (Audit Log), ngăn chặn AI thực thi lệnh nguy hiểm bừa bãi.
