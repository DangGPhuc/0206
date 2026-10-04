# 11. Multi-Stage Event Correlation Engine

> **Nguyên tắc then chốt**: Một hành vi đơn lẻ (như mở PowerShell) có thể chỉ là quản trị viên thao tác hoặc ứng dụng hợp lệ. Nhưng khi **xâu chuỗi các sự kiện liên tiếp theo thời gian và theo quan hệ nhân quả (Causality & Kill Chain)**, hệ thống sẽ xác định được đây là một chiến dịch tấn công có chủ đích.

---

## 1. Cơ chế xâu chuỗi chuỗi tấn công (Attack Kill-Chain)

```
Thời gian: 10:00 (S2)                                                                10:05 (S3)
             │                                                                            │
             ├──► 10:01 [INITIAL ACCESS]:  WINWORD.exe mở file Invoice.docm
             │                                   │ (Parent-Child Link: PID 3212 ➔ 4820)
             ├──► 10:02 [EXECUTION]:       powershell.exe chạy chuỗi Base64 ẩn
             │                                   │ (Network Socket Link: PID 4820 ➔ Remote IP)
             ├──► 10:02 [C2 TRAFFIC]:      powershell kết nối 185.220.101.5:443 (Suricata Alert!)
             │                                   │ (File Drop Link: Tải payload về disk)
             ├──► 10:03 [DROPPER]:         Tạo file mới C:\Users\Public\evil.exe
             │                                   │ (Persistence Link: Thêm khóa khởi động)
             ├──► 10:03 [PERSISTENCE]:     Ghi Registry HKCU\...\Run\Evil = evil.exe
             │                                   │ (Lateral Movement: Kết nối sang máy khác)
             └──► 10:04 [LATERAL MOVEMENT]:PC1 mở kết nối SMB Port 445 sang PC2
```

---

## 2. Các liên kết định danh trong Correlation (Linkage Criteria)

Engine sử dụng các khóa liên kết (Correlation Keys) để tự động nối các sự kiện rời rạc:
1. **Tiến trình cha - con (Parent-Child Relationship)**:
   - `ParentProcessGuid` hoặc `ParentProcessId` nối liền từ tiến trình khai thác sang script interpreter.
2. **Tiến trình & Kết nối mạng (Process-to-Network Link)**:
   - Cùng một PID vừa khởi chạy script thì lập tức mở socket ra ngoài Internet.
3. **Tiến trình & Hoạt động File/Registry**:
   - Tiến trình nhận luồng dữ liệu từ mạng rồi ghi file nhị phân vào thư mục tạm (`AppData`, `Temp`, `Public`).
4. **Liên kết Đa Máy Trạm (Cross-Host Correlation)**:
   - Khi PC1 thực thi payload lạ, trong vòng 60 giây sau xuất hiện lưu lượng SMB/RPC từ IP của PC1 tới IP của PC2 ➔ Nối sự cố PC1 và PC2 vào cùng một **Incident Context**.

---

## 3. Đầu ra của Correlation Engine
- Khi các bước của chuỗi tấn công xuất hiện liên tiếp, Correlation Engine tự động nâng cấp trạng thái:
  $$\text{Isolated Event} \longrightarrow \text{Suspicious Chain} \longrightarrow \text{Confirmed Attack Pattern}$$
- Chuyển toàn bộ chuỗi mắt xích này sang `Scoring Engine` để tính toán điểm rủi ro tổng thể.