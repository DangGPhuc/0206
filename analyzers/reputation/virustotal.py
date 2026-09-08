"""
0206 - VirusTotal Hash Reputation Provider
Queries VirusTotal v3 files API by SHA256 hash.
STRICT PRIVACY GUARANTEES:
- Hash query ONLY. Never uploads binary samples to VirusTotal.
- Does not equate NOT_FOUND with CLEAN.
"""
import os
import json
import hashlib
import urllib.request
import urllib.error
from typing import Optional, Any

from analyzers.reputation.provider import ReputationProvider, ReputationResult, ReputationStatus


class VirusTotalReputationProvider(ReputationProvider):
    """
    Looks up file reputation via VirusTotal v3 REST API.
    Does NOT upload malware samples.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VT_API_KEY", "")

    def lookup_hash(self, sha256_hash: str, evidence_store: Optional[Any] = None) -> ReputationResult:
        """Queries VirusTotal API v3 for hash reputation."""
        clean_hash = sha256_hash.strip().lower()
        if not clean_hash or len(clean_hash) != 64:
            res = ReputationResult(
                provider="VirusTotal",
                query_hash=clean_hash,
                status=ReputationStatus.LOOKUP_FAILED,
                details="Invalid SHA256 hash format."
            )
            return res

        if not self.api_key:
            res = ReputationResult(
                provider="VirusTotal",
                query_hash=clean_hash,
                status=ReputationStatus.NOT_CHECKED,
                details="VirusTotal API key not configured (VT_API_KEY). Hash reputation check skipped."
            )
            return res

        url = f"https://www.virustotal.com/api/v3/files/{clean_hash}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "0206-Triage/2.0.0"
        }

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                raw_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()
                
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0

                # Extract popular threat classification or engine names
                malware_names = []
                results = attrs.get("last_analysis_results", {})
                for engine_data in results.values():
                    name = engine_data.get("result")
                    if name and name not in malware_names:
                        malware_names.append(name)

                if malicious >= 5:
                    status = ReputationStatus.KNOWN_MALICIOUS
                elif malicious >= 1 or suspicious >= 2:
                    status = ReputationStatus.KNOWN_SUSPICIOUS
                elif total > 0 and malicious == 0:
                    status = ReputationStatus.LOW_DETECTION
                else:
                    status = ReputationStatus.NOT_FOUND

                return ReputationResult(
                    provider="VirusTotal",
                    query_hash=clean_hash,
                    status=status,
                    detection_count=malicious + suspicious,
                    total_engines=total,
                    malware_names=malware_names[:10],
                    first_seen=str(attrs.get("first_submission_date")),
                    last_analysis=str(attrs.get("last_analysis_date")),
                    raw_response_hash=raw_hash,
                    details=f"Detections: {malicious}/{total} security engines."
                )

        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ReputationResult(
                    provider="VirusTotal",
                    query_hash=clean_hash,
                    status=ReputationStatus.NOT_FOUND,
                    details="Hash not found in VirusTotal database. NOTE: NOT_FOUND is an absence of threat intel, not proof of clean software."
                )
            return ReputationResult(
                provider="VirusTotal",
                query_hash=clean_hash,
                status=ReputationStatus.LOOKUP_FAILED,
                details=f"VirusTotal API HTTP error: {e.code} {e.reason}"
            )
        except Exception as e:
            return ReputationResult(
                provider="VirusTotal",
                query_hash=clean_hash,
                status=ReputationStatus.LOOKUP_FAILED,
                details=f"Error connecting to VirusTotal: {e}"
            )
