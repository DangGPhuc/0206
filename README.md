# Forensic + Malware in Windows
### Hệ thống Giám sát, Đóng băng và Tái dựng Sự cố An ninh mạng Theo Trục Thời gian

> **Ý tưởng cốt lõi**: Không cố biến mọi thứ thành snapshot nặng nề và không lãng phí tài nguyên chạy AI 24/7.  
> Hệ thống kết hợp chặt chẽ giữa **Lịch sử trạng thái định kỳ (State Snapshots)**, **Dòng chảy sự kiện liên tục (Event Stream)**, **Lưu lượng mạng (Network Sensor)** và **Bảo toàn dữ liệu dễ bốc hơi tức thời (Volatile Preservation)** để trả lời trọn vẹn 2 câu hỏi pháp y số:
> 1. **Cái gì đã thay đổi?** (What changed?)
> 2. **Tại sao và bằng cách nào nó thay đổi?** (Why and how it changed?)

---

## 1. Nguyên lý Nền tảng: EVENT ≠ SNAPSHOT

Trong điều tra số, việc nhầm lẫn giữa sự kiện (Event) và ảnh chụp trạng thái (Snapshot) sẽ dẫn đến sai lầm kiến trúc nghiêm trọng:

```
TRỤC THỜI GIAN
────┬──────────────────┬──────────────────┬──────────────────┬────────────────────►
    ▼                  │                  ▼                  │
SNAPSHOT S2            │             SNAPSHOT S3             │
  (10:00:00)           │               (10:05:00)            │
 ────────────          │              ────────────           │
 Processes:            │              Processes:             │
  - explorer.exe       │               - explorer.exe        │
  - WINWORD.EXE        │               - WINWORD.EXE         │
 Sockets:              │               - powershell.exe  [+] │
  - normal             │               - evil.exe        [+] │
 Registry:             │              Registry:              │
  - normal             │               - Run\Evil        [+] │
                       │              Sockets:               │
                       │               - 185.220.101.5   [+] │
                       │
                       ▼ DÒNG CHẢY SỰ KIỆN LIÊN TỤC (10:00 ➔ 10:05)
                       10:01:14 - [Sysmon 1]  WINWORD sinh ra powershell.exe ngầm
                       10:02:05 - [Zeek DNS]  powershell truy vấn domain c2.evilnetwork.com
                       10:02:08 - [Suricata]  Alert C2 CobaltStrike tới 185.220.101.5:443
                       10:03:22 - [Sysmon 11] Tạo file C:\Users\Public\evil.exe
                       10:03:55 - [Sysmon 13] Ghi Registry HKCU\...\Run\Evil
                       10:04:30 - [Zeek Conn] PC1 kết nối SMB Port 445 sang PC2
```

### Công thức Tái dựng Sự cố giữa 2 Mốc:
$$\text{Investigation Window}(S_2 \to S_3) = \text{State Diff}(S_2, S_3) + \text{Event Stream}(S_2 \to S_3) + \text{Network Traffic}(S_2 \to S_3) + \text{Volatile Evidence}(S_3)$$

---

## 2. 7 Trụ cột Kiến trúc Trọng yếu (Architectural Pillars)

1. **Collector Agent KHÔNG PHẢI là AI Agent**:
   - Chạy dưới dạng Windows Service hoặc tận dụng **Velociraptor Client + Sysmon**.
   - Cực nhẹ, không tốn token AI, có cơ chế Local Spooler buffer khi mất mạng.
2. **Bộ định kỳ thời gian (Scheduler) thuần túy cơ học**:
   - Đúng mỗi 5 phút kích hoạt thu thập trạng thái tĩnh: Process table, Socket list, Autoruns, Services.
   - Hoàn toàn do hệ điều hành/scheduler kích hoạt, không dùng prompt AI.
3. **Cảm biến Mạng hoạt động liên tục 24/7**:
   - **Zeek**: Phân tích metadata giao thức (`conn.log`, `dns.log`, `http.log`, `ssl.log`).
   - **Suricata**: Bắt cảnh báo xâm nhập thời gian thực (`eve.json`).
   - **PCAP Ring Buffer**: Lưu vết gói tin thô dạng cuốn chiếu 15 phút.
4. **Vật lý Bằng chứng Số: Không thể quay lại quá khứ để lấy RAM**:
   - Nếu lúc 10:00 không capture RAM thì lúc 10:05 RAM cũ đã mất vĩnh viễn.
   - Do đó: Định kỳ chỉ lưu metadata nhẹ; **Chỉ khi phát hiện rủi ro lúc 10:05 mới thực hiện Freeze RAM sống ngay lập tức**.
5. **Baseline KHÔNG ĐƠN GIẢN = S2**:
   - Mã độc có thể đã nằm vùng (Dwell Time) từ 09:00. So sánh kép: `S2 vs S3` (Biết vừa xảy ra cái gì) và `LAST_KNOWN_GOOD_BASELINE vs S3` (Biết hệ thống đã lệch chuẩn sạch bao xa).
6. **Normalizer là ETL chuẩn hóa, không phải Summary Report**:
   - Chuyển đổi định dạng log từ mọi nguồn về Common Event Schema (JSON) duy nhất bằng code thuần túy.
7. **Mô hình AI Hai Tầng (Two-Tier AI) - Kiểm soát 100% Token**:
   - **Tầng 1 (AI Triage)**: Bác sĩ cấp cứu, thức dậy khi Risk Score $\ge 70$, trả kết luận nhanh LOW/MED/HIGH trong 3 giây.
   - **Tầng 2 (AI Investigator)**: Thám tử điều tra sâu, chỉ bật khi DFIR bấm `INVESTIGATE`, sử dụng MCP Gateway để gọi các công cụ DFIR chuyên nghiệp.

---

## 3. Bản đồ Tài liệu & Cấu trúc Thư mục Thiết kế

Hệ thống tài liệu thiết kế chi tiết được phân bổ trong repo như sau:

### Part 1: Thu thập Dữ liệu Hạ tầng (Collection Tier)
- [Part1/collector_agent.md](file:///home/kali/Documents/0206/Part1/collector_agent.md): Thiết kế Agent máy trạm, Sysmon, Spooler offline, kiến trúc MVP dùng Velociraptor Client.
- [Part1/network.md](file:///home/kali/Documents/0206/Part1/network.md): Cảm biến mạng liên tục 24/7: Zeek, Suricata, PCAP Ring Buffer 15 phút.

### Part 2: Tầng Máy chủ & Chuẩn hóa (Server Tier)
- [Part2/server/input.md](file:///home/kali/Documents/0206/Part2/server/input.md): Phân tách Ingest (Cửa nhận) và Event Store (Kho lưu trữ theo chuỗi thời gian).
- [Part2/server/normalizer.md](file:///home/kali/Documents/0206/Part2/server/normalizer.md): Bộ chuẩn hóa ETL dữ liệu đa nguồn về Common Event Schema (không dùng AI).
- [Part2/api.md](file:///home/kali/Documents/0206/Part2/api.md): Cổng API bảo mật, kiến trúc MCP Gateway phân quyền, cấm AI gọi trực tiếp PowerShell máy trạm.

### Part 3: Lịch sử Trạng thái & Phát hiện Rủi ro (State & Detection)
- [Part2/state/snapshot.md](file:///home/kali/Documents/0206/Part2/state/snapshot.md): Bản kê Snapshot Manifest 5 phút, cấu trúc trỏ tới state_id và log offset.
- [Part2/state/baseline.md](file:///home/kali/Documents/0206/Part2/state/baseline.md): Last-Known-Good Baseline và phép so sánh kép chống Dwell-Time.
- [Part2/state/diff/detection/detection.md](file:///home/kali/Documents/0206/Part2/state/diff/detection/detection.md): Tổng quan Engine phát hiện đa nguồn xác định.
- [Part2/state/diff/detection/sigma.md](file:///home/kali/Documents/0206/Part2/state/diff/detection/sigma.md): Bộ luật Sigma chuẩn hóa phát hiện hành vi xâm nhập.
- [Part2/state/diff/detection/anomaly.md](file:///home/kali/Documents/0206/Part2/state/diff/detection/anomaly.md): 5 chiều phát hiện dị biệt (Thời gian, Phả hệ tiến trình, Beaconing, Lưu lượng, Di chuyển ngang).
- [Part2/state/diff/detection/correlation.md](file:///home/kali/Documents/0206/Part2/state/diff/detection/correlation.md): Xâu chuỗi tương quan sự kiện thành chuỗi tấn công (Kill Chain).
- [Part2/state/diff/detection/scoring.md](file:///home/kali/Documents/0206/Part2/state/diff/detection/scoring.md): Ma trận tính điểm rủi ro và các ngưỡng hành động (LOW, MEDIUM, HIGH).

### Part 4: Quản trị Sự cố & Chuỗi Bảo quản Bằng chứng (Incident & Evidence)
- [Part2/state/diff/incident/manager.md](file:///home/kali/Documents/0206/Part2/state/diff/incident/manager.md): Trung tâm điều phối sự cố, quản lý vòng đời Incident Ticket.
- [Part2/state/diff/incident/freeze.md](file:///home/kali/Documents/0206/Part2/state/diff/incident/freeze.md): Cơ chế đóng băng dữ liệu dễ bốc hơi ngay tại thời điểm báo động (RFC 3227).
- [Part2/state/diff/incident/preservation.md](file:///home/kali/Documents/0206/Part2/state/diff/incident/preservation.md): Nguyên tắc 4 lớp bảo toàn chuẩn pháp lý (Capture Hash, Ingest Verify, WORM, Working Copy).
- [Part2/state/diff/incident/acquisition.md](file:///home/kali/Documents/0206/Part2/state/diff/incident/acquisition.md): Thu thập điều tra sâu (RAM, Prefetch, MFT, USN Journal, EVTX, Quarantine sample).
- [Part2/state/diff/incident/evidence/evidence.md](file:///home/kali/Documents/0206/Part2/state/diff/incident/evidence/evidence.md): Trung tâm phân loại 5 tầng bằng chứng số.
- [Part2/state/diff/incident/evidence/manifest.md](file:///home/kali/Documents/0206/Part2/state/diff/incident/evidence/manifest.md): Schema Manifest chứng thực danh mục bằng chứng của vụ án.
- [Part2/state/diff/incident/evidence/hashing.md](file:///home/kali/Documents/0206/Part2/state/diff/incident/evidence/hashing.md): Cơ chế băm kép SHA-256 + BLAKE3 và phát hiện can thiệp giả mạo.
- [Part2/state/diff/incident/evidence/object_store.md](file:///home/kali/Documents/0206/Part2/state/diff/incident/evidence/object_store.md): Cấu trúc lưu trữ kho vật lý WORM bất biến.
- [Part2/chain_of_custody.md](file:///home/kali/Documents/0206/Part2/chain_of_custody.md): Hồ sơ lịch sử vòng đời chi tiết từng giây của bằng chứng số.

### Part 5: Trí tuệ Nhân tạo Điều tra & Tái dựng (AI & Reconstruction)
- [Part2/AI/AI.md](file:///home/kali/Documents/0206/Part2/AI/AI.md): Kiến trúc AI Hai Tầng (Fast Triage vs Deep Reasoning Investigator).
- [Part2/AI/triage_agent.md](file:///home/kali/Documents/0206/Part2/AI/triage_agent.md): Bác sĩ cấp cứu AI: Phân loại rủi ro tức thì và khuyến nghị cô lập máy.
- [Part2/AI/investigator_agent.md](file:///home/kali/Documents/0206/Part2/AI/investigator_agent.md): Thám tử điều tra chuyên sâu: Vòng lặp ReAct gọi công cụ qua MCP.
- [Part2/AI/hypothesis_engine.md](file:///home/kali/Documents/0206/Part2/AI/hypothesis_engine.md): Mô hình ACH phân tích giả thuyết cạnh tranh khoa học.
- [Part2/AI/evidence_graph.md](file:///home/kali/Documents/0206/Part2/AI/evidence_graph.md): Đồ thị tri thức sự cố liên kết nhân quả giữa các thực thể và bằng chứng.
- [Part2/AI/reconstruction.md](file:///home/kali/Documents/0206/Part2/AI/reconstruction.md): 5 trụ cột tái dựng: Master Timeline, MITRE ATT&CK, Lineage và Báo cáo DFIR.

### Part 6: Giao diện Công cụ MCP (MCP Gateway Tools)
- [Part2/AI/mcp/mcp.md](file:///home/kali/Documents/0206/Part2/AI/mcp/mcp.md): Kiến trúc cổng MCP an toàn kết nối AI với công cụ DFIR.
- [Part2/AI/mcp/volatility.md](file:///home/kali/Documents/0206/Part2/AI/mcp/volatility.md): Tool MCP phân tích bộ nhớ RAM Volatility 3 (pslist, malfind, netscan).
- [Part2/AI/mcp/evtx.md](file:///home/kali/Documents/0206/Part2/AI/mcp/evtx.md): Tool MCP truy vấn Windows Event Logs và giải mã PowerShell 4104.
- [Part2/AI/mcp/windows_registry.md](file:///home/kali/Documents/0206/Part2/AI/mcp/windows_registry.md): Tool MCP kiểm tra Registry Hive (Run keys, UserAssist, Shimcache).
- [Part2/AI/mcp/filesystem.md](file:///home/kali/Documents/0206/Part2/AI/mcp/filesystem.md): Tool MCP phân tích NTFS $MFT, Prefetch và vạch trần Timestomping.
- [Part2/AI/mcp/yara.md](file:///home/kali/Documents/0206/Part2/AI/mcp/yara.md): Tool MCP quét nhận diện chữ ký mã độc YARA (Cobalt Strike, Webshells).
- [Part2/AI/mcp/velociraptor.md](file:///home/kali/Documents/0206/Part2/AI/mcp/velociraptor.md): Tool MCP gửi tác vụ VQL điều tra máy trạm an toàn.
- [Part2/AI/mcp/zeek.md](file:///home/kali/Documents/0206/Part2/AI/mcp/zeek.md): Tool MCP tra cứu nhật ký giao dịch mạng chuyên sâu.

---

## 4. Kịch bản Vận hành Hoàn chỉnh (End-to-End Walkthrough)

```
[BÌNH THƯỜNG]
  PC1, PC2 (Sysmon + Velo) ──► Continuous Events ──► Server Ingest ──► Event Store
  Network Tap (Zeek + Suricata) ──► Alerts / Logs ──► Server Ingest ──► Event Store
  Scheduler (Mỗi 5 phút) ──► Thu thập State PC1, PC2 ──► Lưu Snapshot S1, S2, S3...

[XẢY RA SỰ CỐ GIỮA S2 VÀ S3 (10:00 ➔ 10:05)]
  1. Người dùng mở file Word ➔ PowerShell ➔ Tải evil.exe ➔ Thêm Run Key ➔ Kết nối PC2:445
  2. Snapshot S3 hoàn thành lúc 10:05:00
  3. Server kích hoạt phép so sánh:
     - PC1@S2 vs PC1@S3: Phát hiện powershell.exe, evil.exe, Run\Evil
     - PC2@S2 vs PC2@S3: Phát hiện kết nối mới từ PC1:445
     - Filter Events Window (10:00, 10:05]: Bắt được lệnh Word sinh PowerShell
     - Suricata: Cảnh báo C2 Cobalt Strike lúc 10:02:08
  4. Detection Scoring: Điểm rủi ro đạt 105 điểm (Vượt ngưỡng 70) ➔ HIGH ALERT lúc 10:05:03!

[PHẢN ỨNG TỨC THÌ (PRESERVATION & TRIAGE)]
  1. Incident Manager tạo Incident INC-20261002-001
  2. Phát lệnh Freeze tức thì:
     - PC1 dump toàn bộ RAM (memory.raw) và các tiến trình khả nghi
     - Network Sensor khóa lát cắt PCAP (10:00 - 10:10)
     - Tính hash SHA-256 / BLAKE3 và lưu vào WORM Object Store
  3. Đánh thức AI Triage Agent ➔ Xuất kết luận khẩn cấp: "CRITICAL - Phishing to C2 & Lateral"

[ĐIỀU TRA CHUYÊN SÂU (DEEP INVESTIGATION)]
  1. Chuyên gia DFIR bấm [INVESTIGATE]
  2. AI Investigator Agent khởi động vòng lặp ReAct:
     - Gọi MCP Volatility (malfind) ➔ Phát hiện shellcode tiêm vào RAM
     - Gọi MCP EVTX ➔ Trích xuất khối code PowerShell de-obfuscate tải mã độc
     - Gọi MCP Filesystem ➔ Vạch trần evil.exe sửa ngày tháng tạo (Timestomping)
     - Gọi MCP YARA ➔ Xác nhận mã độc là Cobalt Strike Beacon
     - Gọi MCP Velociraptor ➔ Phát hiện Scheduled Task UpdaterService cài cắm trên PC2
  3. Xây dựng Evidence Knowledge Graph & Master Timeline
  4. Xuất Báo cáo Incident Report hoàn chỉnh, cung cấp IOCs và khuyến nghị khắc phục cho DFIR.
```
