# 22. AI Architecture Overview (Two-Tier Incident Intelligence)

> **Giải quyết triệt để bài toán chi phí & Token Quota**:  
> **Không có bất kỳ model AI nào chạy liên tục 24/7 hoặc định kỳ mỗi 5 phút**.  
> Hệ thống giám sát vận hành 100% bằng mã nguồn xác định (Deterministic Detection). AI chỉ được kích hoạt (Wake-up) theo mô hình **Hai tầng thông minh (Two-Tier Operating Model)** khi có sự cố thực sự xảy ra.

---

## 1. Sơ đồ phối hợp Hai Tầng AI

```
          Detection Engine (Risk Score >= 70 lúc 10:05:03)
                                 │
                                 ▼
   ┌───────────────────────────────────────────────────────────┐
   │                  TẦNG 1: AI TRIAGE AGENT                  │
   │               (Bác sĩ cấp cứu - Fast Response)            │
   ├───────────────────────────────────────────────────────────┤
   │ - Đầu vào: State Diff tóm tắt + Top Alerts + Event Stream │
   │ - Model: Cỡ nhỏ, nhanh, tiết kiệm (hoặc Local LLM)        │
   │ - Nhiệm vụ: Đánh giá phân loại LOW / MEDIUM / HIGH        │
   │ - Thời gian chạy: 3 - 5 giây                              │
   └─────────────────────────────┬─────────────────────────────┘
                                 │
                                 ▼ Trả kết quả sơ bộ cho DFIR
   ┌───────────────────────────────────────────────────────────┐
   │               CHUYÊN GIA DFIR (Human-in-the-Loop)         │
   │           "Phát hiện xâm nhập nghiêm trọng trên PC1.      │
   │             Bấm [INVESTIGATE] để tiến hành điều tra sâu"  │
   └─────────────────────────────┬─────────────────────────────┘
                                 │
                                 ▼ DFIR phê duyệt (hoặc Auto-Policy)
   ┌───────────────────────────────────────────────────────────┐
   │               TẦNG 2: AI INVESTIGATOR AGENT               │
   │            (Thám tử điều tra sâu - Deep Reasoning)        │
   ├───────────────────────────────────────────────────────────┤
   │ - Vòng lặp: ReAct (Reasoning + Acting)                    │
   │ - Công cụ: Gọi các công cụ DFIR chuyên sâu qua MCP        │
   │   (Volatility, YARA, Registry, EVTX, Filesystem, Zeek)    │
   │ - Nhiệm vụ: Dựng giả thuyết, tìm bằng chứng, vẽ sơ đồ     │
   │   tấn công và sinh báo cáo kỹ thuật toàn diện             │
   └───────────────────────────────────────────────────────────┘
```

---

## 2. So sánh đặc tính 2 tầng AI

| Tiêu chí | Tầng 1: AI Triage Agent | Tầng 2: AI Investigator Agent |
| :--- | :--- | :--- |
| **Vai trò tương đương** | Bác sĩ trực cấp cứu tiếp nhận bệnh nhân | Hội đồng chuyên khoa mổ xẻ chẩn đoán |
| **Thời điểm bật** | Ngay khi Detection báo Risk Score $\ge 70$ | Khi DFIR bấm duyệt điều tra sâu |
| **Yêu cầu năng lực Model** | Xử lý ngữ cảnh nhanh, phân loại chính xác, chi phí thấp | Khả năng suy luận logic sâu (Reasoning), gọi công cụ (Tool-Use / Function Calling) |
| **Độ trễ phản hồi** | Tức thì (vài giây) | Vài phút (chạy nhiều vòng lặp suy luận) |
| **Tương tác công cụ** | Không gọi công cụ ngoài (Chỉ đọc tóm tắt) | Gọi linh hoạt hàng loạt MCP Tools |
| **Sản phẩm đầu ra** | Điểm phân loại rủi ro & Lý do tóm tắt | Đồ thị bằng chứng, Timeline, Attack Graph và Báo cáo điều tra hoàn chỉnh |
