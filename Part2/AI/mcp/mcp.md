# 28. Model Context Protocol (MCP) Gateway

> **Vai trò**: Cung cấp "đôi tay và con mắt" cho AI Investigator.  
> MCP (Model Context Protocol) là giao thức chuẩn hóa mở cho phép LLM gọi các công cụ điều tra pháp y chuyên dụng một cách có cấu trúc, an toàn và hoàn toàn có thể kiểm toán (Auditable).

---

## 1. Sơ đồ kiến trúc MCP Gateway an toàn

```
                             ┌─────────────────────────────────┐
                             │      AI INVESTIGATOR AGENT      │
                             └────────────────┬────────────────┘
                                              │ JSON-RPC / MCP
                                              ▼
                             ┌─────────────────────────────────┐
                             │       DFIR MCP GATEWAY          │
                             │  (Kiểm tra quyền, Sanitize,     │
                             │   Ghi nhật ký Audit Log)        │
                             └────────────────┬────────────────┘
                                              │
         ┌──────────────────┬─────────────────┼──────────────────┬──────────────────┐
         ▼                  ▼                 ▼                  ▼                  ▼
  ┌──────────────┐   ┌──────────────┐  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │  Volatility  │   │     EVTX     │  │   Registry   │   │  Filesystem  │   │  YARA Engine │
  │   MCP Tool   │   │   MCP Tool   │  │   MCP Tool   │   │   MCP Tool   │   │   MCP Tool   │
  └──────┬───────┘   └──────┬───────┘  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
         │                  │                 │                  │                  │
         └──────────────────┼─────────────────┴──────────────────┼──────────────────┘
                            │
                            ▼
        ┌────────────────────────────────────────────────────────┐
        │  DFIR Server Evidence Store & Velociraptor Server API  │
        │             (Tuyệt đối KHÔNG chạy lệnh tùy tiện        │
        │              trực tiếp bằng PowerShell trên PC)        │
        └────────────────────────────────────────────────────────┘
```

---

## 2. Danh mục công cụ MCP (Tool Catalog)

Mỗi công cụ MCP cung cấp cho AI định dạng hàm rõ ràng (Schema):

1. **[volatility.md](file:///home/kali/Documents/0206/Part2/AI/mcp/volatility.md)**: Phân tích file ảnh bộ nhớ RAM `memory.raw` (pslist, malfind, netscan, cmdline).
2. **[evtx.md](file:///home/kali/Documents/0206/Part2/AI/mcp/evtx.md)**: Truy vấn nhật ký sự kiện Windows (Security, System, Sysmon, PowerShell).
3. **[windows_registry.md](file:///home/kali/Documents/0206/Part2/AI/mcp/windows_registry.md)**: Phân tích các file Registry Hive (Run keys, Services, UserAssist, Shimcache).
4. **[filesystem.md](file:///home/kali/Documents/0206/Part2/AI/mcp/filesystem.md)**: Truy vấn NTFS `$MFT`, Prefetch, và phát hiện Timestomping.
5. **[yara.md](file:///home/kali/Documents/0206/Part2/AI/mcp/yara.md)**: Quét chữ ký nhận diện mã độc trên file hoặc bộ nhớ.
6. **[velociraptor.md](file:///home/kali/Documents/0206/Part2/AI/mcp/velociraptor.md)**: Ra lệnh cho Velociraptor Server thực thi VQL trích xuất artifact trên endpoint.
7. **[zeek.md](file:///home/kali/Documents/0206/Part2/AI/mcp/zeek.md)**: Truy vấn lịch sử kết nối mạng, DNS và chứng chỉ SSL trong sự cố.

---

## 3. Các quy tắc an toàn nghiêm ngặt của Gateway
- **Zero Direct Shell**: AI không có quyền mở bash/cmd/PowerShell trực tiếp tới PC1 hay PC2.
- **Param Sanitization**: Mọi tham số đường dẫn file, PID, regex gửi vào tool đều được validate để tránh Path Traversal hoặc Command Injection vào server điều tra.
- **Audit Ledger**: Mỗi lệnh gọi công cụ MCP đều được ghi lại vào nhật ký `chain_of_custody` của vụ án.