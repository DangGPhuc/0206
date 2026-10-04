# 18. Evidence Manifest (Danh mục kiểm kê bằng chứng)

> **Định nghĩa**: **Manifest** là tài liệu JSON chuẩn hóa đóng vai trò là "Mục lục chứng thực" cho toàn bộ các file bằng chứng thuộc về một sự cố (Incident). Manifest gắn kết chặt chẽ từng file với nguồn gốc máy trạm, mốc thời gian, công cụ thu thập và mã băm mật mã học.

---

## 1. Cấu trúc Schema chuẩn của Incident Manifest

```json
{
  "manifest_version": "2.0",
  "incident_id": "INC-20261002-001",
  "created_at": "2026-10-02T10:06:05.000Z",
  "case_title": "Suspicious Word Macro Execution and Lateral Movement to PC2",
  "total_evidence_count": 4,
  "artifacts": [
    {
      "evidence_id": "EVD-20261002-0042",
      "type": "memory_raw",
      "filename": "PC1_20261002_100511.raw",
      "source_host": "PC1",
      "source_ip": "192.168.1.10",
      "size_bytes": 17179869184,
      "hashes": {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "blake3": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"
      },
      "acquisition_tool": "Velociraptor Windows.Memory.Acquisition (WinPmem)",
      "collected_at": "2026-10-02T10:05:36Z",
      "storage_uri": "s3://evidence-vault/INC-20261002-001/PC1_20261002_100511.raw",
      "is_read_only": true
    },
    {
      "evidence_id": "EVD-20261002-0043",
      "type": "pcap_slice",
      "filename": "incident_window_1000_1010.pcap",
      "source_host": "NETWORK_SENSOR_01",
      "size_bytes": 268435456,
      "hashes": {
        "sha256": "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
      },
      "acquisition_tool": "PCAP Ring Buffer Extractor",
      "collected_at": "2026-10-02T10:05:40Z",
      "storage_uri": "s3://evidence-vault/INC-20261002-001/incident_window_1000_1010.pcap",
      "is_read_only": true
    },
    {
      "evidence_id": "EVD-20261002-0044",
      "type": "malware_binary",
      "filename": "evil.exe",
      "source_host": "PC1",
      "source_path": "C:\\Users\\Public\\evil.exe",
      "size_bytes": 1048576,
      "hashes": {
        "sha256": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
      },
      "acquisition_tool": "Velociraptor Generic.Client.DiskQuarantine",
      "collected_at": "2026-10-02T10:05:45Z",
      "storage_uri": "s3://evidence-vault/INC-20261002-001/evil.exe.quarantine",
      "is_read_only": true
    },
    {
      "evidence_id": "EVD-20261002-0045",
      "type": "state_diff_checkpoint",
      "filename": "diff_PC1_S2_vs_S3.json",
      "source_host": "DFIR_SERVER_CORE",
      "size_bytes": 38912,
      "hashes": {
        "sha256": "9b74c9897bac770ffc029102a200c6001759f3382ea73b8257cb98c4a64d95f0"
      },
      "acquisition_tool": "Server State Diff Engine",
      "collected_at": "2026-10-02T10:05:02Z",
      "storage_uri": "s3://evidence-vault/INC-20261002-001/diff_PC1_S2_vs_S3.json",
      "is_read_only": true
    }
  ]
}
```
