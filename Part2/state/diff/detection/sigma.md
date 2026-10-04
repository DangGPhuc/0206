# 9. Sigma Rules Matcher

> **Định nghĩa**: **Sigma** là tiêu chuẩn mở quốc quy định tập luật phát hiện hành vi tấn công mạng trên nhật ký sự kiện (Event Logs). Trong hệ thống này, Sigma Engine quét trực tiếp trên luồng dữ liệu đã được chuẩn hóa bởi `Normalizer` và các đối tượng mới xuất hiện trong `State Diff`.

---

## 1. Cơ chế hoạt động trong Pipeline

```
  Normalized Events / Diff Objects
                 │
                 ▼
  ┌─────────────────────────────┐
  │     SIGMA RULES ENGINE      │ ◄─── Thư viện quy tắc Sigma (YML converted to AST)
  │                             │
  │  ├─ Condition Evaluation    │
  │  ├─ Regex & String Matching │
  │  └─ Mitre ATT&CK Mapping    │
  └──────────────┬──────────────┘
                 │
                 ▼ Match Found!
  ┌─────────────────────────────┐
  │   Sigma Alert Output:       │
  │   - Rule ID & Name          │
  │   - Severity: HIGH          │
  │   - Base Risk Score: +30    │
  │   - MITRE: T1059.001        │
  └──────────────┬──────────────┘
                 │
                 ▼
       Correlation & Scoring
```

---

## 2. Các nhóm quy tắc Sigma trọng yếu trong hệ thống

### Rule 1: Office Spawning PowerShell / Command Prompt (Initial Execution)
- **Tình huống**: Người dùng mở file Word chứa macro độc hại kích hoạt PowerShell chạy ngầm.
- **Tiêu chí lọc**:
  ```yaml
  title: Office Application Spawning Windows PowerShell
  status: production
  logsource:
    category: process_creation
    product: windows
  detection:
    selection:
      parent_process_name:
        - 'WINWORD.EXE'
        - 'EXCEL.EXE'
        - 'POWERPNT.EXE'
      process_name:
        - 'powershell.exe'
        - 'cmd.exe'
        - 'wscript.exe'
        - 'cscript.exe'
    condition: selection
  level: high
  mitre_attack:
    - T1059.001
  ```

### Rule 2: Living-off-the-land Binary (LOLBin) Download (Ingress Tool Transfer)
- **Tình huống**: Sử dụng `certutil` hoặc `bitsadmin` để tải payload mã độc qua mạng.
- **Tiêu chí lọc**:
  ```yaml
  selection:
    process_name: 'certutil.exe'
    command_line|contains:
      - '-urlcache'
      - '-split'
  level: medium
  ```

### Rule 3: Persistence qua Windows Registry Run Keys (Persistence)
- **Tình huống**: Ghi khóa khởi động cùng Windows tại `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- **Tiêu chí lọc**:
  ```yaml
  selection:
    target_object|contains:
      - '\CurrentVersion\Run\'
      - '\CurrentVersion\RunOnce\'
    action: 'registry_set_value'
  level: medium
  ```

### Rule 4: Tắt tính năng bảo mật Windows Defender (Defense Evasion)
- **Tình huống**: Kẻ tấn công chạy lệnh tắt real-time monitoring của Antivirus.
- **Tiêu chí lọc**:
  ```yaml
  selection:
    command_line|contains: 'Set-MpPreference -DisableRealtimeMonitoring $true'
  level: critical
  ```