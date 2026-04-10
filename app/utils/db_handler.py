import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


class DatabaseManager:
    """
    SQLite-based database manager for the TLS Fingerprinting platform.

    Manages:
    - TLS event records
    - Known JA3 whitelist
    - Unknown / candidate fingerprints
    - PCAP file processing lifecycle
    - Application logs
    - Application settings (key-value config)
    - Inter-process command queue
    """

    def __init__(self, db_path: Optional[str] = None):
        default_path = os.environ.get("DB_PATH", "data/tls_fingerprint.db")
        self.db_path = db_path or default_path

        db_file = Path(self.db_path)
        db_file.parent.mkdir(parents=True, exist_ok=True)

        self._initialize_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_database(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ja3_hash TEXT NOT NULL UNIQUE,
                    ja3_string TEXT,
                    app_name TEXT NOT NULL,
                    category TEXT DEFAULT 'known',
                    confidence REAL DEFAULT 100.0,
                    source TEXT DEFAULT 'manual',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tls_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    tls_version TEXT,
                    ja3_hash TEXT NOT NULL,
                    ja3_string TEXT,
                    prediction TEXT,
                    confidence REAL DEFAULT 0.0,
                    status TEXT DEFAULT 'unknown',
                    pcap_file TEXT,
                    raw_metadata TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS candidates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ja3_hash TEXT NOT NULL UNIQUE,
                    ja3_string TEXT,
                    predicted_app TEXT,
                    confidence REAL DEFAULT 0.0,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    seen_count INTEGER DEFAULT 1,
                    promoted INTEGER DEFAULT 0
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pcap_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT NOT NULL,
                    file_path TEXT NOT NULL UNIQUE,
                    file_size INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'detected',
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed_at TIMESTAMP,
                    records_extracted INTEGER DEFAULT 0,
                    records_logged INTEGER DEFAULT 0,
                    error_message TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    level TEXT NOT NULL,
                    component TEXT NOT NULL,
                    message TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_config (
                    config_key TEXT PRIMARY KEY,
                    config_value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS app_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_name TEXT NOT NULL,
                    payload TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed_at TIMESTAMP,
                    result_message TEXT
                )
            """)

            # Indices
            for stmt in [
                "CREATE INDEX IF NOT EXISTS idx_tls_events_timestamp ON tls_events(timestamp DESC)",
                "CREATE INDEX IF NOT EXISTS idx_tls_events_ja3_hash ON tls_events(ja3_hash)",
                "CREATE INDEX IF NOT EXISTS idx_whitelist_ja3_hash ON whitelist(ja3_hash)",
                "CREATE INDEX IF NOT EXISTS idx_candidates_ja3_hash ON candidates(ja3_hash)",
                "CREATE INDEX IF NOT EXISTS idx_pcap_files_status ON pcap_files(status)",
                "CREATE INDEX IF NOT EXISTS idx_pcap_files_first_seen ON pcap_files(first_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_app_logs_timestamp ON app_logs(timestamp DESC)",
                "CREATE INDEX IF NOT EXISTS idx_app_logs_component ON app_logs(component)",
                "CREATE INDEX IF NOT EXISTS idx_app_commands_status ON app_commands(status)",
                "CREATE INDEX IF NOT EXISTS idx_app_commands_created_at ON app_commands(created_at DESC)",
            ]:
                cursor.execute(stmt)

            conn.commit()

    # ----------------------------
    # APP CONFIG
    # ----------------------------

    def set_config(self, key: str, value: Optional[str]) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO app_config (config_key, config_value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(config_key) DO UPDATE SET
                    config_value = excluded.config_value,
                    updated_at = CURRENT_TIMESTAMP
            """, (key, value))
            conn.commit()

    def get_config(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT config_value FROM app_config WHERE config_key = ? LIMIT 1
            """, (key,))
            row = cursor.fetchone()
            if not row:
                return default
            return row["config_value"] if row["config_value"] is not None else default

    def get_all_config(self) -> Dict[str, Optional[str]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT config_key, config_value FROM app_config ORDER BY config_key ASC")
            rows = cursor.fetchall()
            return {row["config_key"]: row["config_value"] for row in rows}

    def set_many_config(self, values: Dict[str, Optional[str]]) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for key, value in values.items():
                cursor.execute("""
                    INSERT INTO app_config (config_key, config_value, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(config_key) DO UPDATE SET
                        config_value = excluded.config_value,
                        updated_at = CURRENT_TIMESTAMP
                """, (key, value))
            conn.commit()

    # ----------------------------
    # APP COMMANDS
    # ----------------------------

    def enqueue_command(self, command_name: str, payload: Optional[str] = None) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO app_commands (command_name, payload, status) VALUES (?, ?, 'pending')
            """, (command_name, payload))
            conn.commit()
            return cursor.lastrowid

    def get_pending_commands(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, command_name, payload, status, created_at, processed_at, result_message
                FROM app_commands WHERE status = 'pending'
                ORDER BY created_at ASC, id ASC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def complete_command(
        self,
        command_id: int,
        status: str = "done",
        result_message: Optional[str] = None
    ) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE app_commands
                SET status = ?, processed_at = CURRENT_TIMESTAMP, result_message = ?
                WHERE id = ?
            """, (status, result_message, command_id))
            conn.commit()

    def get_recent_commands(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, command_name, payload, status, created_at, processed_at, result_message
                FROM app_commands ORDER BY created_at DESC, id DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # ----------------------------
    # WHITELIST OPERATIONS
    # ----------------------------

    def get_whitelist_match(self, ja3_hash: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, ja3_hash, ja3_string, app_name, category, confidence, source, notes, created_at
                FROM whitelist WHERE ja3_hash = ? LIMIT 1
            """, (ja3_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def add_whitelist_entry(
        self,
        ja3_hash: str,
        app_name: str,
        ja3_string: Optional[str] = None,
        category: str = "known",
        confidence: float = 100.0,
        source: str = "manual",
        notes: Optional[str] = None
    ) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO whitelist
                (ja3_hash, ja3_string, app_name, category, confidence, source, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ja3_hash, ja3_string, app_name, category, confidence, source, notes))
            conn.commit()

    def get_all_whitelist_entries(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, ja3_hash, ja3_string, app_name, category, confidence, source, notes, created_at
                FROM whitelist ORDER BY created_at DESC
            """)
            return [dict(row) for row in cursor.fetchall()]

    # ----------------------------
    # TLS EVENT LOGGING
    # ----------------------------

    def log_event(
        self,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        ja3_hash: str,
        ja3_string: Optional[str] = None,
        prediction: str = "Unknown",
        confidence: float = 0.0,
        status: str = "unknown",
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        tls_version: Optional[str] = None,
        pcap_file: Optional[str] = None,
        raw_metadata: Optional[str] = None
    ) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tls_events
                (src_ip, dst_ip, src_port, dst_port, tls_version,
                 ja3_hash, ja3_string, prediction, confidence, status,
                 pcap_file, raw_metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                src_ip, dst_ip, src_port, dst_port, tls_version,
                ja3_hash, ja3_string, prediction, confidence, status,
                pcap_file, raw_metadata
            ))
            conn.commit()
            return cursor.lastrowid

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port,
                       tls_version, ja3_hash, ja3_string,
                       prediction, confidence, status, pcap_file
                FROM tls_events ORDER BY timestamp DESC, id DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # ----------------------------
    # CANDIDATE / UNKNOWN MANAGEMENT
    # ----------------------------

    def upsert_candidate(
        self,
        ja3_hash: str,
        predicted_app: str,
        confidence: float,
        ja3_string: Optional[str] = None
    ) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id FROM candidates WHERE ja3_hash = ? LIMIT 1
            """, (ja3_hash,))
            existing = cursor.fetchone()

            if existing:
                cursor.execute("""
                    UPDATE candidates
                    SET predicted_app = ?,
                        confidence = ?,
                        ja3_string = COALESCE(?, ja3_string),
                        last_seen = CURRENT_TIMESTAMP,
                        seen_count = seen_count + 1
                    WHERE ja3_hash = ?
                """, (predicted_app, confidence, ja3_string, ja3_hash))
            else:
                cursor.execute("""
                    INSERT INTO candidates (ja3_hash, ja3_string, predicted_app, confidence)
                    VALUES (?, ?, ?, ?)
                """, (ja3_hash, ja3_string, predicted_app, confidence))

            conn.commit()

    def get_candidates(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, ja3_hash, ja3_string, predicted_app,
                       confidence, first_seen, last_seen, seen_count, promoted
                FROM candidates ORDER BY last_seen DESC, id DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def promote_candidate_to_whitelist(
        self,
        ja3_hash: str,
        app_name: Optional[str] = None,
        source: str = "auto-promoted"
    ) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ja3_hash, ja3_string, predicted_app, confidence
                FROM candidates WHERE ja3_hash = ? LIMIT 1
            """, (ja3_hash,))
            candidate = cursor.fetchone()
            if not candidate:
                return False

            final_app_name = app_name or candidate["predicted_app"] or "Unknown App"
            cursor.execute("""
                INSERT OR REPLACE INTO whitelist
                (ja3_hash, ja3_string, app_name, category, confidence, source, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                candidate["ja3_hash"], candidate["ja3_string"],
                final_app_name, "known", candidate["confidence"],
                source, "Promoted from candidates table"
            ))
            cursor.execute("""
                UPDATE candidates SET promoted = 1, last_seen = CURRENT_TIMESTAMP
                WHERE ja3_hash = ?
            """, (ja3_hash,))
            conn.commit()
            return True

    # ----------------------------
    # APP LOGS
    # ----------------------------

    def log_app_event(self, level: str, component: str, message: str) -> int:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO app_logs (level, component, message)
                VALUES (?, ?, ?)
            """, (level.upper(), component.lower(), message))
            conn.commit()
            return cursor.lastrowid

    def get_recent_logs(
        self,
        limit: int = 100,
        level: Optional[str] = None,
        component: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT id, timestamp, level, component, message FROM app_logs WHERE 1=1"
            params: List[Any] = []
            if level:
                query += " AND level = ?"
                params.append(level.upper())
            if component:
                query += " AND component = ?"
                params.append(component.lower())
            query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    # ----------------------------
    # PCAP FILE TRACKING
    # ----------------------------

    def upsert_pcap_file(
        self,
        file_name: str,
        file_path: str,
        file_size: int = 0,
        status: str = "detected"
    ) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pcap_files (file_name, file_path, file_size, status)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(file_path) DO UPDATE SET
                    file_name = excluded.file_name,
                    file_size = excluded.file_size,
                    status = excluded.status
            """, (file_name, file_path, file_size, status))
            conn.commit()

    def update_pcap_status(
        self,
        file_path: str,
        status: str,
        records_extracted: Optional[int] = None,
        records_logged: Optional[int] = None,
        error_message: Optional[str] = None
    ) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE pcap_files
                SET status = ?,
                    processed_at = CASE
                        WHEN ? IN ('processed', 'no_tls_records', 'error')
                        THEN CURRENT_TIMESTAMP
                        ELSE processed_at
                    END,
                    records_extracted = COALESCE(?, records_extracted),
                    records_logged = COALESCE(?, records_logged),
                    error_message = ?
                WHERE file_path = ?
            """, (status, status, records_extracted, records_logged, error_message, file_path))
            conn.commit()

    def get_pcap_files(
        self,
        limit: int = 200,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = """
                SELECT id, file_name, file_path, file_size, status,
                       first_seen, processed_at, records_extracted,
                       records_logged, error_message
                FROM pcap_files WHERE 1=1
            """
            params: List[Any] = []
            if status:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY first_seen DESC, id DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_last_processed_pcap(self) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, file_name, file_path, file_size, status,
                       first_seen, processed_at, records_extracted,
                       records_logged, error_message
                FROM pcap_files WHERE processed_at IS NOT NULL
                ORDER BY processed_at DESC, id DESC LIMIT 1
            """)
            row = cursor.fetchone()
            return dict(row) if row else None

    # ----------------------------
    # DASHBOARD / ANALYTICS
    # ----------------------------

    def get_summary_metrics(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) AS total FROM tls_events")
            total_events = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) AS total FROM whitelist")
            whitelist_count = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) AS total FROM candidates")
            candidate_count = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) AS total FROM tls_events WHERE status = 'known'")
            known_events = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) AS total FROM tls_events WHERE status = 'unknown'")
            unknown_events = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) AS total FROM pcap_files WHERE status IN ('detected', 'processing')")
            active_pcap_jobs = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) AS total FROM pcap_files WHERE status = 'processed'")
            processed_pcap_count = cursor.fetchone()["total"]

            last_processed = self.get_last_processed_pcap()

            return {
                "total_events": total_events,
                "whitelist_count": whitelist_count,
                "candidate_count": candidate_count,
                "known_events": known_events,
                "unknown_events": unknown_events,
                "active_pcap_jobs": active_pcap_jobs,
                "processed_pcap_count": processed_pcap_count,
                "last_processed_pcap": last_processed["file_name"] if last_processed else None,
            }

    def get_top_ja3_hashes(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ja3_hash,
                       MAX(ja3_string) AS ja3_string,
                       COUNT(*) AS hit_count,
                       MAX(prediction) AS latest_prediction,
                       MAX(timestamp) AS last_seen
                FROM tls_events
                GROUP BY ja3_hash
                ORDER BY hit_count DESC, last_seen DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_top_predictions(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COALESCE(prediction, 'Unknown') AS prediction,
                       COUNT(*) AS hit_count,
                       MAX(timestamp) AS last_seen
                FROM tls_events
                GROUP BY COALESCE(prediction, 'Unknown')
                ORDER BY hit_count DESC, last_seen DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_port_distribution(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT dst_port, COUNT(*) AS hit_count
                FROM tls_events
                WHERE dst_port IS NOT NULL
                GROUP BY dst_port
                ORDER BY hit_count DESC, dst_port ASC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_recent_unique_fingerprints(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ja3_hash,
                       MAX(ja3_string) AS ja3_string,
                       MAX(prediction) AS latest_prediction,
                       MAX(status) AS latest_status,
                       MAX(timestamp) AS last_seen,
                       COUNT(*) AS occurrences
                FROM tls_events
                GROUP BY ja3_hash
                ORDER BY last_seen DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_event_trend(self, limit: int = 24) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_bucket,
                       COUNT(*) AS event_count
                FROM tls_events
                GROUP BY hour_bucket
                ORDER BY hour_bucket DESC
                LIMIT ?
            """, (limit,))
            result = [dict(row) for row in cursor.fetchall()]
            result.reverse()
            return result

    def seed_sample_whitelist(self) -> None:
        sample_entries = [
            {
                "ja3_hash": "e6573e91e6eb777c0933c5b8f97f10cd",
                "ja3_string": "771,4865-4866-4867-49195-49199-49196-49200,0-11-10-35-16,29-23-24,0",
                "app_name": "Chrome (Modern)",
                "category": "browser",
                "confidence": 99.0,
                "source": "demo-seed",
                "notes": "Google Chrome typical TLS fingerprint"
            },
            {
                "ja3_hash": "a0e9f5d64349fb13191bc781f81f42e1",
                "ja3_string": "771,4865-4867-4866-49195-49196,0-10-11-13-16,29-23-24,0",
                "app_name": "Firefox (Modern)",
                "category": "browser",
                "confidence": 99.0,
                "source": "demo-seed",
                "notes": "Mozilla Firefox typical TLS fingerprint"
            },
            {
                "ja3_hash": "773906b0efdefa24a7f2b8eb6985bf37",
                "ja3_string": "771,49200-49196-49192,0-11-10-35-16,23-24,0",
                "app_name": "Safari (macOS)",
                "category": "browser",
                "confidence": 97.0,
                "source": "demo-seed",
                "notes": "Apple Safari typical TLS fingerprint"
            },
            {
                "ja3_hash": "b32309a26951912be7dba376398d89de",
                "ja3_string": "771,4865-4866-4867,0-11-10-13-35,29-23,0",
                "app_name": "curl (HTTP client)",
                "category": "cli-tool",
                "confidence": 95.0,
                "source": "demo-seed",
                "notes": "curl command-line HTTP client"
            },
        ]
        for entry in sample_entries:
            self.add_whitelist_entry(**entry)