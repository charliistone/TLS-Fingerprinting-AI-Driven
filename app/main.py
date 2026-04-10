import argparse
import os as _os
import sys as _sys
# Ensure the project root is in sys.path so `app.*` imports work
# whether launched as `python app/main.py`, `sudo python app/main.py`, etc.
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import logging
import os
import shutil
import sys
import time
import webbrowser
from pathlib import Path
from typing import List, Optional, Set

from app.models.predictor import TLSPredictor
from app.processing.extractor import process_pcap_file
from app.utils.db_handler import DatabaseManager


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


class TLSFingerprintPipeline:
    """
    Main orchestrator for the TLS Fingerprinting platform.

    Capabilities:
    - Optionally launches a live TShark ring-buffer capture
    - Watches a directory for new PCAP files
    - Extracts TLS ClientHello → JA3 fingerprints via tshark
    - Classifies fingerprints via whitelist + heuristics
    - Persists all data to SQLite
    - Optionally launches the Streamlit dashboard
    - Processes pending commands from the DB (hot config reload)
    """

    def __init__(
        self,
        capture_dir: str = "data/captures",
        processed_dir: str = "data/processed",
        poll_interval: Optional[int] = None,
        stable_seconds: Optional[int] = None,
        start_capture: bool = False,
        interface: Optional[str] = None,
        capture_filter: Optional[str] = None,
        ring_duration: Optional[int] = None,
        ring_files: Optional[int] = None,
        with_dashboard: bool = False,
        dashboard_port: Optional[int] = None,
        tshark_path: Optional[str] = None,
        capture_owner: str = "backend",
    ):
        self.capture_dir = Path(capture_dir)
        self.processed_dir = Path(processed_dir)
        self.start_capture = start_capture
        self.with_dashboard = with_dashboard
        self.capture_owner = capture_owner.strip().lower()

        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)

        self.db = DatabaseManager()
        self.predictor = TLSPredictor(self.db)

        self.poll_interval = self._resolve_int("poll_interval", poll_interval, "POLL_INTERVAL", 5)
        self.stable_seconds = self._resolve_int("stable_seconds", stable_seconds, "STABLE_SECONDS", 3)
        self.interface = self._resolve_str("capture_interface", interface, "CAPTURE_INTERFACE", "")
        self.capture_filter = self._resolve_str("capture_filter", capture_filter, "CAPTURE_FILTER", "")
        self.ring_duration = self._resolve_int("ring_duration", ring_duration, "RING_DURATION", 30)
        self.ring_files = self._resolve_int("ring_files", ring_files, "RING_FILES", 10)
        self.dashboard_port = self._resolve_int("dashboard_port", dashboard_port, "DASHBOARD_PORT", 8501)
        self.tshark_path = self._resolve_tshark(tshark_path)

        self.processed_signatures: Set[str] = set()
        self.capture_process = None
        self.dashboard_process = None

    # ---------------------------------
    # CONFIG RESOLUTION  (CLI > ENV > DB > default)
    # ---------------------------------

    def _resolve_str(self, config_key: str, provided: Optional[str], env_key: str, fallback: str) -> str:
        if provided is not None and str(provided).strip():
            return str(provided).strip()
        env = os.environ.get(env_key)
        if env and env.strip():
            return env.strip()
        db = self.db.get_config(config_key)
        if db and str(db).strip():
            return str(db).strip()
        return fallback

    def _resolve_int(self, config_key: str, provided: Optional[int], env_key: str, fallback: int) -> int:
        if provided is not None:
            return int(provided)
        env = os.environ.get(env_key)
        if env:
            try:
                return int(env)
            except ValueError:
                pass
        db = self.db.get_config(config_key)
        if db:
            try:
                return int(db)
            except ValueError:
                pass
        return fallback

    def _resolve_tshark(self, provided: Optional[str]) -> str:
        if provided and str(provided).strip():
            return str(provided).strip()
        env = os.environ.get("TSHARK_PATH")
        if env and env.strip():
            return env.strip()
        db = self.db.get_config("tshark_path")
        if db and str(db).strip():
            return str(db).strip()
        return shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"

    # ---------------------------------
    # INTERNAL LOGGING
    # ---------------------------------

    def _log(self, level: str, component: str, message: str) -> None:
        level_upper = level.upper()
        getattr(logging, level_upper.lower(), logging.info)(f"[{component}] {message}")
        try:
            self.db.log_app_event(level_upper, component, message)
        except Exception as e:
            logging.warning("Could not write log to DB: %s", e)

    def _register_pcap(self, file_path: Path, status: str = "detected") -> None:
        try:
            self.db.upsert_pcap_file(
                file_name=file_path.name,
                file_path=str(file_path.resolve()),
                file_size=file_path.stat().st_size if file_path.exists() else 0,
                status=status
            )
        except Exception as e:
            logging.warning("Could not register PCAP (%s): %s", file_path, e)

    # ---------------------------------
    # HOT APPLY / COMMAND PROCESSING
    # ---------------------------------

    def reload_settings(self) -> None:
        self.interface = self._resolve_str("capture_interface", None, "CAPTURE_INTERFACE", "")
        self.capture_filter = self._resolve_str("capture_filter", None, "CAPTURE_FILTER", "")
        self.ring_duration = self._resolve_int("ring_duration", None, "RING_DURATION", 30)
        self.ring_files = self._resolve_int("ring_files", None, "RING_FILES", 10)
        self.poll_interval = self._resolve_int("poll_interval", None, "POLL_INTERVAL", 5)
        self.stable_seconds = self._resolve_int("stable_seconds", None, "STABLE_SECONDS", 3)
        self.tshark_path = self._resolve_tshark(None)

    def process_pending_commands(self) -> None:
        if self.capture_owner != "backend":
            return
        for command in self.db.get_pending_commands(limit=10):
            command_id = command["id"]
            command_name = command["command_name"]
            try:
                if command_name == "apply_capture_settings":
                    self._log("INFO", "system", "Command received: apply_capture_settings")
                    self.reload_settings()
                    self.stop_tshark_capture()
                    if self.start_capture:
                        started = self.start_tshark_capture()
                        msg = f"Capture restarted | interface={self.interface}" if started else "Settings applied, capture not started (no interface)"
                    else:
                        msg = "Settings applied. Backend running without live capture."
                    self.db.complete_command(command_id, "done", msg)
                    self._log("INFO", "system", f"Command completed: {msg}")
                else:
                    msg = f"Unknown command: {command_name}"
                    self.db.complete_command(command_id, "failed", msg)
                    self._log("ERROR", "system", msg)
            except Exception as e:
                self.db.complete_command(command_id, "failed", str(e))
                self._log("ERROR", "system", f"Command failed ({command_name}): {e}")

    # ---------------------------------
    # DASHBOARD
    # ---------------------------------

    def start_dashboard(self) -> None:
        if self.dashboard_process and self.dashboard_process.poll() is None:
            return
        import subprocess
        cmd = [
            sys.executable, "-m", "streamlit", "run", "app/ui/dashboard.py",
            "--server.port", str(self.dashboard_port),
            "--server.headless", "true"
        ]
        self._log("INFO", "dashboard", f"Launching dashboard (port={self.dashboard_port})")
        try:
            self.dashboard_process = subprocess.Popen(cmd)
            time.sleep(2)
            if self.dashboard_process.poll() is None:
                self._log("INFO", "dashboard", "Dashboard started successfully")
                try:
                    webbrowser.open(f"http://localhost:{self.dashboard_port}")
                except Exception:
                    pass
            else:
                self._log("ERROR", "dashboard", "Dashboard exited immediately. Port may be in use.")
        except Exception as e:
            self._log("ERROR", "dashboard", f"Failed to launch dashboard: {e}")
            raise

    def stop_dashboard(self) -> None:
        if self.dashboard_process and self.dashboard_process.poll() is None:
            self._log("INFO", "dashboard", "Stopping dashboard")
            self.dashboard_process.terminate()
            try:
                self.dashboard_process.wait(timeout=5)
            except Exception:
                self.dashboard_process.kill()

    # ---------------------------------
    # LIVE CAPTURE
    # ---------------------------------

    def start_tshark_capture(self) -> bool:
        if not self.interface:
            self._log("WARNING", "capture", "Live capture not started: capture_interface not configured. Set it in Settings.")
            return False

        import subprocess
        output_file = self.capture_dir / "live_tls_capture.pcapng"
        cmd = [
            self.tshark_path,
            "-i", self.interface,
            "-w", str(output_file),
            "-b", f"duration:{self.ring_duration}",
            "-b", f"files:{self.ring_files}",
            "-Q",
        ]
        if self.capture_filter:
            cmd.extend(["-f", self.capture_filter])

        self._log("INFO", "capture",
            f"Starting TShark | interface={self.interface} | ring_duration={self.ring_duration} | ring_files={self.ring_files}")

        try:
            self.capture_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._log("INFO", "capture", f"TShark running | path={self.tshark_path}")
            return True
        except FileNotFoundError:
            self._log("ERROR", "capture", "TShark not found. Install Wireshark/TShark first.")
            raise
        except Exception as e:
            self._log("ERROR", "capture", f"TShark failed to start: {e}")
            raise

    def stop_tshark_capture(self) -> None:
        if self.capture_process and self.capture_process.poll() is None:
            self._log("INFO", "capture", "Stopping TShark capture")
            self.capture_process.terminate()
            try:
                self.capture_process.wait(timeout=5)
            except Exception:
                self.capture_process.kill()

    # ---------------------------------
    # FILE DISCOVERY
    # ---------------------------------

    def build_file_signature(self, file_path: Path) -> str:
        stat = file_path.stat()
        return f"{file_path.resolve()}::{stat.st_mtime_ns}::{stat.st_size}"

    def discover_pcap_files(self) -> List[Path]:
        candidates: List[Path] = []
        for pattern in ("*.pcap", "*.pcapng"):
            candidates.extend(self.capture_dir.glob(pattern))
        candidates = sorted(candidates, key=lambda p: p.stat().st_mtime)

        ready: List[Path] = []
        now = time.time()
        for file_path in candidates:
            try:
                age = now - file_path.stat().st_mtime
                sig = self.build_file_signature(file_path)
            except FileNotFoundError:
                continue

            if sig in self.processed_signatures:
                continue

            self._register_pcap(file_path, "detected")

            if age >= self.stable_seconds:
                ready.append(file_path)

        return ready

    # ---------------------------------
    # PROCESSING
    # ---------------------------------

    def process_single_pcap(self, pcap_file: Path) -> int:
        resolved = str(pcap_file.resolve())
        self._register_pcap(pcap_file, "processing")
        self.db.update_pcap_status(resolved, "processing")
        self._log("INFO", "watcher", f"Processing PCAP: {pcap_file.name}")

        try:
            self._log("INFO", "extractor", f"Extractor started: {pcap_file.name}")
            records = process_pcap_file(str(pcap_file), tshark_path=self.tshark_path)
        except Exception as e:
            self.db.update_pcap_status(resolved, "error", 0, 0, str(e))
            self._log("ERROR", "extractor", f"Extractor error ({pcap_file.name}): {e}")
            return 0

        if not records:
            self.processed_signatures.add(self.build_file_signature(pcap_file))
            self.db.update_pcap_status(resolved, "no_tls_records", 0, 0, None)
            self._log("WARNING", "extractor", f"No TLS ClientHello records found: {pcap_file.name}")
            return 0

        self._log("INFO", "extractor", f"{pcap_file.name}: extracted {len(records)} records")
        processed_count = 0

        for record in records:
            try:
                result = self.predictor.predict(record)
                self.db.log_event(
                    src_ip=record.get("src_ip"),
                    dst_ip=record.get("dst_ip"),
                    src_port=record.get("src_port"),
                    dst_port=record.get("dst_port"),
                    tls_version=record.get("tls_version"),
                    ja3_hash=record.get("ja3_hash"),
                    ja3_string=record.get("ja3_string"),
                    prediction=result.get("prediction", "Unknown"),
                    confidence=float(result.get("confidence", 0.0)),
                    status=result.get("status", "unknown"),
                    pcap_file=str(pcap_file),
                    raw_metadata=record.get("raw_metadata"),
                )
                processed_count += 1
            except Exception as e:
                self._log("ERROR", "predictor", f"Record processing failed ({pcap_file.name}): {e}")

        self.processed_signatures.add(self.build_file_signature(pcap_file))
        self.db.update_pcap_status(resolved, "processed", len(records), processed_count, None)
        self._log("INFO", "watcher",
            f"PCAP processed: {pcap_file.name} | extracted={len(records)} | logged={processed_count}")

        return processed_count

    def process_existing_files_once(self) -> int:
        files = self.discover_pcap_files()
        if not files:
            self._log("INFO", "watcher", f"No ready PCAPs found in: {self.capture_dir.resolve()}")
            return 0
        total = 0
        for f in files:
            total += self.process_single_pcap(f)
        return total

    # ---------------------------------
    # INTERFACE LISTING
    # ---------------------------------

    @staticmethod
    def list_interfaces(tshark_path: Optional[str] = None) -> int:
        import subprocess
        resolved = tshark_path or os.environ.get("TSHARK_PATH") or shutil.which("tshark") or ""
        try:
            result = subprocess.run([resolved, "-D"], capture_output=True, text=True, encoding="utf-8")
        except FileNotFoundError:
            logging.error("TShark not found. Install Wireshark/TShark first.")
            return 1
        if result.returncode != 0:
            logging.error("Could not list interfaces:\n%s", result.stderr.strip())
            return result.returncode
        print(result.stdout)
        return 0

    # ---------------------------------
    # RUN LOOP
    # ---------------------------------

    def run_forever(self) -> None:
        self._log("INFO", "system", "TLS Fingerprinting backend started")
        self._log("INFO", "system", f"Capture dir: {self.capture_dir.resolve()}")
        self._log("INFO", "system", f"Interface: {self.interface or '(not configured)'}")
        self._log("INFO", "system", f"TShark path: {self.tshark_path}")
        self._log("INFO", "system", f"Capture filter: {self.capture_filter or '(none)'}")
        self._log("INFO", "system", f"Capture owner: {self.capture_owner}")

        if self.with_dashboard:
            self.start_dashboard()

        if self.start_capture:
            self.start_tshark_capture()
        else:
            self._log("INFO", "capture", "Live capture disabled. Watching capture dir for existing PCAPs.")

        try:
            while True:
                self.process_pending_commands()
                for pcap_file in self.discover_pcap_files():
                    self.process_single_pcap(pcap_file)
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            self._log("WARNING", "system", "Interrupted by user")
        finally:
            self.stop_tshark_capture()
            self.stop_dashboard()
            self._log("INFO", "system", "Backend stopped")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI-Driven TLS Fingerprinting Pipeline")
    parser.add_argument("--capture-dir", default=os.environ.get("CAPTURE_DIR", "data/captures"))
    parser.add_argument("--capture-owner", default=os.environ.get("CAPTURE_OWNER", "backend"), choices=["backend", "host"])
    parser.add_argument("--processed-dir", default=os.environ.get("PROCESSED_DIR", "data/processed"))
    parser.add_argument("--poll-interval", type=int, default=None)
    parser.add_argument("--stable-seconds", type=int, default=None)
    parser.add_argument("--start-capture", action="store_true")
    parser.add_argument("--interface", default=None)
    parser.add_argument("--capture-filter", default=None)
    parser.add_argument("--ring-duration", type=int, default=None)
    parser.add_argument("--ring-files", type=int, default=None)
    parser.add_argument("--with-dashboard", action="store_true")
    parser.add_argument("--dashboard-port", type=int, default=None)
    parser.add_argument("--tshark-path", default=None)
    parser.add_argument("--once", action="store_true", help="Process existing PCAPs once and exit")
    parser.add_argument("--list-interfaces", action="store_true", help="List TShark interfaces and exit")
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()

    if args.list_interfaces:
        raise SystemExit(TLSFingerprintPipeline.list_interfaces(args.tshark_path or None))

    pipeline = TLSFingerprintPipeline(
        capture_dir=args.capture_dir,
        processed_dir=args.processed_dir,
        poll_interval=args.poll_interval,
        stable_seconds=args.stable_seconds,
        start_capture=args.start_capture,
        interface=args.interface,
        capture_filter=args.capture_filter,
        ring_duration=args.ring_duration,
        ring_files=args.ring_files,
        with_dashboard=args.with_dashboard,
        dashboard_port=args.dashboard_port,
        tshark_path=args.tshark_path,
        capture_owner=args.capture_owner,
    )

    if args.once:
        total = pipeline.process_existing_files_once()
        logging.info("One-shot complete. Total logged records: %d", total)
    else:
        pipeline.run_forever()