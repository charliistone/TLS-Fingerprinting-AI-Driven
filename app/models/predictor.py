import json
from typing import Any, Dict, List, Optional

from app.utils.db_handler import DatabaseManager


class TLSPredictor:
    """
    Hybrid decision engine for TLS fingerprint classification.

    Flow:
    1. Fast Path — if the JA3 hash is in the whitelist DB, return 'known'.
    2. Unknown Path — apply rule-based heuristics and write to candidates table.
    """

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()

    # ---------------------------------
    # PUBLIC API
    # ---------------------------------

    def predict(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a TLS record dict.

        Expected keys: ja3_hash, ja3_string, tls_version, dst_port, raw_metadata.

        Returns:
            dict with: prediction, confidence, status, source
        """
        ja3_hash = record.get("ja3_hash")
        ja3_string = record.get("ja3_string")
        tls_version = record.get("tls_version")
        dst_port = record.get("dst_port")
        raw_metadata = record.get("raw_metadata")

        if not ja3_hash:
            return {
                "prediction": "Invalid Record",
                "confidence": 0.0,
                "status": "unknown",
                "source": "validation"
            }

        # Fast path: whitelist lookup
        whitelist_match = self.db.get_whitelist_match(ja3_hash)
        if whitelist_match:
            return {
                "prediction": whitelist_match["app_name"],
                "confidence": float(whitelist_match.get("confidence", 100.0)),
                "status": "known",
                "source": "whitelist"
            }

        # Unknown path: heuristic inference
        result = self._heuristic_predict(
            ja3_hash=ja3_hash,
            ja3_string=ja3_string,
            tls_version=tls_version,
            dst_port=dst_port,
            raw_metadata=raw_metadata
        )

        self.db.upsert_candidate(
            ja3_hash=ja3_hash,
            predicted_app=result["prediction"],
            confidence=result["confidence"],
            ja3_string=ja3_string
        )

        return result

    # ---------------------------------
    # INTERNAL HELPERS
    # ---------------------------------

    def _heuristic_predict(
        self,
        ja3_hash: str,
        ja3_string: Optional[str],
        tls_version: Optional[str],
        dst_port: Optional[int],
        raw_metadata: Optional[str]
    ) -> Dict[str, Any]:
        metadata = self._parse_raw_metadata(raw_metadata)
        extensions = self._parse_numeric_list(metadata.get("tls.handshake.extension.type"))
        ciphers = self._parse_numeric_list(metadata.get("tls.handshake.ciphersuites"))
        groups = self._parse_numeric_list(metadata.get("tls.handshake.extensions_supported_group"))

        has_sni = 0 in extensions
        has_supported_groups = 10 in extensions
        has_ec_point = 11 in extensions
        has_sig_algs = 13 in extensions
        has_alpn = 16 in extensions

        cipher_count = len(ciphers)
        ext_count = len(extensions)
        group_count = len(groups)

        # Rule 1: Modern browser-like HTTPS client
        if (
            dst_port in {443, 8443}
            and tls_version in {"771", "772"}
            and has_sni
            and has_supported_groups
            and has_ec_point
            and has_sig_algs
            and has_alpn
            and cipher_count >= 5
            and ext_count >= 5
        ):
            return {
                "prediction": "Browser-like HTTPS Client",
                "confidence": 82.0,
                "status": "candidate",
                "source": "heuristic"
            }

        # Rule 2: Generic HTTPS TLS client
        if dst_port in {443, 8443} and tls_version in {"769", "770", "771", "772"}:
            return {
                "prediction": "Generic HTTPS/TLS Client",
                "confidence": 68.0,
                "status": "candidate",
                "source": "heuristic"
            }

        # Rule 3: Mail client candidate
        if dst_port in {465, 587, 993, 995}:
            return {
                "prediction": "Mail Client Candidate",
                "confidence": 70.0,
                "status": "candidate",
                "source": "heuristic"
            }

        # Rule 4: Messaging / mobile push
        if dst_port in {5222, 5223, 5228}:
            return {
                "prediction": "Messaging / Mobile Service Candidate",
                "confidence": 64.0,
                "status": "candidate",
                "source": "heuristic"
            }

        # Rule 5: DNS over TLS
        if dst_port == 853:
            return {
                "prediction": "DNS-over-TLS Client",
                "confidence": 76.0,
                "status": "candidate",
                "source": "heuristic"
            }

        # Rule 6: Structured JA3 but unknown
        if ja3_string and "," in ja3_string and (group_count > 0 or cipher_count > 0):
            return {
                "prediction": "Unknown TLS Client",
                "confidence": 45.0,
                "status": "unknown",
                "source": "heuristic"
            }

        return {
            "prediction": "Unclassified TLS Client",
            "confidence": 20.0,
            "status": "unknown",
            "source": "heuristic"
        }

    def _parse_raw_metadata(self, raw_metadata: Optional[str]) -> Dict[str, Any]:
        if not raw_metadata:
            return {}
        try:
            data = json.loads(raw_metadata)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _parse_numeric_list(self, value: Optional[str]) -> List[int]:
        if value is None:
            return []
        value = str(value).strip().strip('"')
        if not value:
            return []
        tokens = value.replace(";", ",").split(",")
        parsed: List[int] = []
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            try:
                if token.lower().startswith("0x"):
                    parsed.append(int(token, 16))
                else:
                    parsed.append(int(token))
            except ValueError:
                continue
        return parsed