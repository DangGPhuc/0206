# 24. AI Investigator Agent (Autonomous DFIR Reasoning Agent)

> **Vai trò**: Đóng vai trò là "Thám tử điều tra chuyên sâu".  
> AI Investigator chỉ được kích hoạt khi chuyên gia DFIR phê duyệt điều tra (`INVESTIGATE`) hoặc chính sách tự động cho phép. Agent sử dụng vòng lặp suy luận **ReAct (Reasoning + Acting)** tương tác với các công cụ điều tra qua **MCP Gateway** để lần theo dấu vết, kiểm tra giả thuyết và dựng lại toàn bộ bức tranh sự cố.

---

## 1. Vòng lặp điều tra ReAct (Reasoning & Tool Execution Loop)

```
                              ┌────────────────────────────────────────┐
                              │     KHỞI TẠO ĐIỀU TRA SỰ CỐ            │
                              │     (Incident INC-20261002-001)        │
                              └───────────────────┬────────────────────┘
                                                  │
                                                  ▼
                        ┌────────────────────────────────────────────────────┐
                ┌──────►│ 1. THOUGHT & QUESTION (Đặt câu hỏi / Giả thuyết)   │
                │       │ "Liệu powershell.exe có inject mã độc vào RAM?"    │
                │       └─────────────────────────┬──────────────────────────┘
                │                                 │
                │                                 ▼
                │       ┌────────────────────────────────────────────────────┐
                │       │ 2. ACTION: MCP TOOL CALL (Gọi công cụ phù hợp)     │
                │       │ mcp.volatility(tool="windows.malfind", pid=4820)   │
                │       └─────────────────────────┬──────────────────────────┘
                │                                 │
                │                                 ▼
                │       ┌────────────────────────────────────────────────────┐
                │       │ 3. OBSERVATION (Quan sát kết quả từ công cụ)       │
                │       │ Phát hiện vùng nhớ PAGE_EXECUTE_READWRITE có mã MZ │
                │       └─────────────────────────┬──────────────────────────┘
                │                                 │
                │                                 ▼
                │       ┌────────────────────────────────────────────────────┐
                │       │ 4. SYNTHESIS (Cập nhật Đồ thị & Giả thuyết)        │
                │       │ Đánh dấu: [CONFIRMED] Process Injection            │
                │       └─────────────────────────┬──────────────────────────┘
                │                                 │
                └─── Chưa làm rõ mọi nghi vấn ────┴─── Đã xác định đầy đủ Root Cause & Scope
                                                      │
                                                      ▼
                                       ┌──────────────────────────────┐
                                       │ Xuất Reconstruction & Báo cáo│
                                       └──────────────────────────────┘
```

---

## 2. Kịch bản từng bước của AI Investigator trong sự cố mẫu

1. **Bước 1 (Xác minh điểm xâm nhập ban đầu - Initial Access)**:
   - *Suy luận*: Word gọi PowerShell, vậy file Word đến từ đâu?
   - *Hành động MCP*: `mcp.filesystem.get_file_metadata("C:\\Users\\victim\\Downloads\\Invoice.docm")` và `mcp.evtx.query("EventID=15")` (Zone.Identifier Mark-of-the-Web).
   - *Kết quả*: File tải từ Outlook Web lúc 09:58 qua email lừa đảo.

2. **Bước 2 (Xác minh hành vi trong bộ nhớ - In-Memory Execution)**:
   - *Suy luận*: Tiến trình `evil.exe` đang làm gì trong RAM lúc 10:05?
   - *Hành động MCP*: `mcp.volatility.netscan(memory_evidence_id="EVD-0042")`.
   - *Kết quả*: Phát hiện socket ngầm đang liên lạc với máy chủ C2 `185.220.101.5` trên cổng 443.

3. **Bước 3 (Xác minh phạm vi lây lan - Lateral Movement Blast Radius)**:
   - *Suy luận*: PC1 kết nối sang PC2 qua cổng 445, liệu PC2 đã bị chiếm quyền chưa?
   - *Hành động MCP*: `mcp.velociraptor.query(host="PC2", artifact="Windows.System.TaskScheduler")` và kiểm tra Security Event Log 4624 (Logon Type 3 - Network).
   - *Kết quả*: Thấy tài khoản quản trị bị lợi dụng để tạo Remote Scheduled Task mang tên `UpdaterService` trên PC2 trỏ tới file mã độc vừa sao chép qua SMB.

---

## 3. Ranh giới kiểm soát an toàn (Guardrails)
- **Chỉ đọc (Read-Only Safety)**: AI Investigator qua MCP chỉ có quyền đọc, truy vấn và phân tích dữ liệu; không có quyền thực thi các lệnh phá hủy hay tự ý xóa bằng chứng trên máy đích.
- **Giới hạn số vòng lặp (Max Iterations)**: Giới hạn tối đa 15 - 20 bước suy luận để tránh vòng lặp vô hạn và kiểm soát chi phí.