# 17. Evidence Store & Inventory Management

> **Vai trò**: Trung tâm quản lý toàn bộ các mẫu bằng chứng số (Forensic Artifacts) thu thập được trong sự cố.  
> Mỗi bằng chứng đều được cấp một định danh duy nhất (`Evidence ID`), được bảo vệ tính toàn vẹn bằng mật mã học, gắn liền với bản kê (`Manifest`) và theo dõi nghiêm ngặt qua chuỗi bảo quản (`Chain of Custody`).

---

## 1. Sơ đồ phân loại bằng chứng số (Evidence Taxonomy)

```
                              ┌──────────────────────────────────┐
                              │          EVIDENCE HUB            │
                              └─────────────────┬────────────────┘
                                                │
         ┌──────────────────┬───────────────────┼──────────────────┬──────────────────┐
         ▼                  ▼                   ▼                  ▼                  ▼
    1. Volatile        2. Disk & OS         3. Network         4. State           5. Derived
    (Dễ bốc hơi)       (Hệ thống đĩa)       (Giao tiếp mạng)   (Lịch sử Server)   (Sản phẩm sau PT)
    ───────────────    ───────────────      ────────────────   ────────────────   ─────────────────
    - memory.raw       - System.evtx        - incident.pcap    - PC1_State_S2     - vol_pslist.json
    - process.dmp      - Security.evtx      - zeek_conn.log    - PC1_State_S3     - yara_matches.txt
    - socket_dump.json - NTUSER.DAT         - suricata.json    - State_Diff.json  - extracted_strings
    - clipboard.txt    - $MFT / Prefetch    - dns_stream.json  - Baseline_Ref     - timeline.csv
```

---

## 2. Quy trình xử lý bằng chứng số

1. **Thu nhận & Định danh**:
   - Mỗi file khi vào hệ thống được sinh mã `EVD-YYYYMMDD-XXXX` (Ví dụ: `EVD-20261002-0042`).
2. **Ký số & Đóng gói Metadata**:
   - Ghi nhận kích thước chính xác đến từng byte, thời điểm bắt đầu/kết thúc thu thập, công cụ thực hiện, và tính toán mã băm SHA-256 / SHA-3.
3. **Phân bổ lưu trữ vật lý**:
   - Lưu trữ dữ liệu nhị phân thô trong [object_store.md](file:///home/kali/Documents/0206/Part2/state/diff/incident/evidence/object_store.md).
   - Lưu trữ metadata và danh mục kiểm kê trong [manifest.md](file:///home/kali/Documents/0206/Part2/state/diff/incident/evidence/manifest.md).
   - Kiểm tra tính toàn vẹn định kỳ qua [hashing.md](file:///home/kali/Documents/0206/Part2/state/diff/incident/evidence/hashing.md).
   - Ghi nhận nhật ký vòng đời trong [chain_of_custody.md](file:///home/kali/Documents/0206/Part2/chain_of_custody.md).
