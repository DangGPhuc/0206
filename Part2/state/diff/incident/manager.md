# 13. Incident Manager (Incident Orchestration Subsystem)

> **Vai trò**: Trung tâm điều phối khi có báo động đỏ từ Detection Engine ($\text{Risk Score} \ge 70$).  
> Incident Manager chịu trách nhiệm gom tụ ngữ cảnh, phát lệnh bảo toàn bằng chứng khẩn cấp, kích hoạt đóng băng dữ liệu dễ bốc hơi và chuẩn bị đầu vào cho AI Triage và chuyên gia DFIR.

---

## 1. Quy trình điều phối sự cố (Incident Orchestration Workflow)

```
                       ┌────────────────────────────────────────┐
                       │ Detection Engine phát tín hiệu ALERT   │
                       │ (Risk Score >= 70 lúc 10:05:03)        │
                       └───────────────────┬────────────────────┘
                                           │
                                           ▼
                       ┌────────────────────────────────────────┐
                       │            INCIDENT MANAGER            │
                       └───────────────────┬────────────────────┘
                                           │
       ┌───────────────────────────────────┼───────────────────────────────────┐
       ▼                                   ▼                                   ▼
┌──────────────┐                  ┌──────────────────┐                ┌──────────────────┐
│ 1. TẠO HỒ SƠ │                  │ 2. PHÁT LỆNH     │                │ 3. ĐÓNG GÓI      │
│   INCIDENT   │                  │ BẢO TOÀN (FREEZE)│                │ NGỮ CẢNH BAN ĐẦU │
└──────┬───────┘                  └────────┬─────────┘                └────────┬─────────┘
       │                                   │                                   │
       │ Incident ID:                      │ - Yêu cầu Velo capture RAM PC1    │ - State S2 (10:00)
       │ INC-20261002-01                   │ - Khóa PCAP Ring (10:00 - 10:10)  │ - State S3 (10:05)
       │ Mức độ: HIGH                      │ - Giữ socket/process live         │ - Events (10:00 - 10:05)
       │ Máy liên quan: PC1, PC2           │ - Trích xuất file khả nghi        │ - Suricata/Zeek alerts
       └───────────────────────────────────┼───────────────────────────────────┘
                                           │
                                           ▼
                       ┌────────────────────────────────────────┐
                       │     ĐÁNH THỨC AI TRIAGE & BÁO DFIR     │
                       └────────────────────────────────────────┘
```

---

## 2. Cấu trúc Hồ sơ Sự cố (Incident Context Schema)

Mỗi sự cố được đóng gói thành một đối tượng trung tâm chứa đầy đủ tham chiếu tới bằng chứng:

```json
{
  "incident_id": "INC-20261002-001",
  "created_at": "2026-10-02T10:05:03.120Z",
  "severity": "HIGH",
  "trigger": {
    "detection_type": "correlation_threshold",
    "risk_score": 105,
    "primary_rule": "Office_Spawn_PowerShell_Followed_By_C2_And_Lateral"
  },
  "affected_hosts": ["PC1", "PC2"],
  "time_window": {
    "snapshot_start_ref": "global_snap_s2_1000",
    "snapshot_end_ref": "global_snap_s3_1005",
    "exact_start": "2026-10-02T10:00:00Z",
    "exact_end": "2026-10-02T10:05:03Z"
  },
  "evidence_manifest_ref": "manifest_INC-20261002-001.json",
  "status": "TRIAGING",
  "assigned_ai": "ai_triage_agent_v1",
  "dfir_lead": null
}
```

---

## 3. Các trạng thái vòng đời của một Incident (Incident Lifecycle)

1. **TRIAGING**: AI Triage đang phân tích gói tóm tắt và đánh giá mức độ khẩn cấp.
2. **PRESERVING**: Hệ thống đang hoàn tất thu thập RAM, trích xuất PCAP và kiểm tra băm tính toàn vẹn (Hashing).
3. **INVESTIGATING**: DFIR phê duyệt hoặc AI Investigator đang dùng MCP truy vấn sâu các artifact.
4. **CONTAINED**: Đã cách ly máy trạm bị nhiễm (Isolate host qua Velociraptor / Firewall).
5. **RESOLVED / REPORTED**: Đã dựng lại cuộc tấn công (Reconstruction) và xuất báo cáo hoàn chỉnh cho DFIR.