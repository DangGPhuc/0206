"""
0206 - ThreatFox Hash Reputation Provider
Queries abuse.ch ThreatFox by IOC hash.
STRICT PRIVACY GUARANTEES:
- Hash query ONLY. Never uploads samples.
- Does not equate NOT_FOUND with CLEAN.
"""
import json
import urllib.request
import urllib.error
from typing import Optional, Any
from analyzers.reputation.provider import ReputationProvider, ReputationResult, ReputationStatus


class ThreatFoxReputationProvider(ReputationProvider):
    """
    Looks up file reputation via ThreatFox API (abuse.ch).
    Hash-only lookup, zero sample uploads.
    """

    def __init__(self, api_key: Optional[str] = None, offline: bool = False):
        self.api_key = api_key
        self.offline = offline

    def lookup_hash(self, sha256_hash: str, evidence_store: Optional[Any] = None) -> ReputationResult:
        clean_hash = sha256_hash.strip().lower()
        if self.offline:
            return ReputationResult(
                provider="ThreatFox",
                query_hash=clean_hash,
                status=ReputationStatus.SKIPPED_OFFLINE,
                details="Reputation lookup skipped in offline mode."
            )
        if not clean_hash or len(clean_hash) != 64:
            return ReputationResult(
                provider="ThreatFox",
                query_hash=clean_hash,
                status=ReputationStatus.LOOKUP_FAILED,
                details="Invalid SHA256 hash format."
            )

        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = json.dumps({"query": "search_hash", "hash": clean_hash}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "0206-Triage/2.0.0"
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        req = urllib.request.Request(url, data=payload, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                query_status = res_data.get("query_status", "")

                if query_status == "ok":
                    data_list = res_data.get("data", [])
                    item = data_list[0] if data_list else {}
                    threat_type = item.get("threat_type_desc") or item.get("threat_type") or "IOC"
                    malware = item.get("malware_printable") or "UnknownMalware"
                    return ReputationResult(
                        provider="ThreatFox",
                        query_hash=clean_hash,
                        status=ReputationStatus.KNOWN_MALICIOUS,
                        detection_count=len(data_list),
                        total_engines=1,
                        malware_names=[malware],
                        first_seen=item.get("first_seen"),
                        details=f"IOC listed on ThreatFox: {malware} ({threat_type})"
                    )
                elif query_status in ("no_result", "hash_not_found"):
                    return ReputationResult(
                        provider="ThreatFox",
                        query_hash=clean_hash,
                        status=ReputationStatus.NOT_FOUND,
                        details="Hash not listed on ThreatFox IOC database (absence != clean)."
                    )
                else:
                    return ReputationResult(
                        provider="ThreatFox",
                        query_hash=clean_hash,
                        status=ReputationStatus.LOOKUP_FAILED,
                        details=f"ThreatFox API returned status: {query_status}"
                    )
        except Exception as e:
            return ReputationResult(
                provider="ThreatFox",
                query_hash=clean_hash,
                status=ReputationStatus.LOOKUP_FAILED,
                details=f"Network error querying ThreatFox: {e}"
            )
