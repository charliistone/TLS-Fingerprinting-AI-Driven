import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

from app.utils.db_handler import DatabaseManager


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


class HostCaptureAgent:
    """
    Standalone host-side capture agent.

    Responsibilities:
    - Discovers network interfaces via `tshark -D`
    - Writes discovered interfaces to data/runtime/detected_interfaces.json
    - Manages the TShark ring-buffer capture subprocess
    - Watches for config changes in the DB and hot-reloads
    - Writes its own status to data/runtime/host_capture_status.json

    Run this directly on the host (not inside Docker) with:
        python host_capture_agent.py
    """

    def __init__(self):
        self.db = DatabaseManager()

        self.data_dir = Path("data")
        self.capture_dir = self.data_dir / "captures"
        self.runtime_dir = self.data_dir / "runtime"

        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)

        self.interfaces_file = self.runtime_dir / "detected_interfaces.json"
        self.agent_status_file = self.runtime_dir / "host_capture_status.json"

        self.capture_process = None
        self.current_signature = None

    def _log(self, level: str, message: str) -> None:
        level = level.upper()
        if level == "ERROR":
            logging.error(message)
        elif level == "WARNING":
            logging.warning(message)
        else:
            logging.info(message)

    def _write_json_atomic(self, path: Path, data) -> None:
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp_path.replace(path)

    def _get_config(self) -> dict:
        tshark_path = (
            self.db.get_config("tshark_path")
            or os.environ.get("TSHARK_PATH")
            or shutil.which("tshark")
            or r"C:\Program Files\Wireshark\tshark.exe"
        )

        capture_interface = self.db.get_config("capture_interface", "") or ""
        capture_filter = self.db.get_config("capture_filter", "") or ""

        try:
            ring_duration = int(self.db.get_config("ring_duration", "30") or "30")
        except ValueError:
            ring_duration = 30

        try:
            ring_files = int(self.db.get_config("ring_files", "10") or "10")
        except ValueError:
            ring_files = 10

        return {
            "capture_interface": capture_interface,
            "capture_filter": capture_filter,
            "ring_duration": ring_duration,
            "ring_files": ring_files,
            "tshark_path": tshark_path,
        }

    def get_detected_interfaces(self) -> list:
        cfg = self._get_config()
        tshark_path = cfg["tshark_path"]

        try:
            result = subprocess.run(
                [tshark_path, "-D"],
                capture_output=True,
                text=True,
                encoding="utf-8"
            )
        except Exception as e:
            self._log("ERROR", f"Failed to list interfaces: {e}")
            return []

        if result.returncode != 0:
            self._log("ERROR", f"tshark -D failed: {result.stderr.strip()}")
            return []

        interfaces = []
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split(". ", 1)
            if len(parts) == 2 and parts[0].isdigit():
                interfaces.append({"index": parts[0], "label": parts[1], "display": line})
            else:
                interfaces.append({"index": "", "label": line, "display": line})

        return interfaces

    def sync_interfaces_to_file(self) -> None:
        interfaces = self.get_detected_interfaces()
        self._write_json_atomic(self.interfaces_file, interfaces)
        self._log("INFO", f"Interfaces synced → {self.interfaces_file} ({len(interfaces)} entries)")

    def write_agent_status(self, status: str, message: str, config: dict = None) -> None:
        payload = {
            "status": status,
            "message": message,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "config": config or {},
        }
        self._write_json_atomic(self.agent_status_file, payload)

    def _build_signature(self, cfg: dict) -> str:
        return "|".join([
            cfg["capture_interface"],
            cfg["capture_filter"],
            str(cfg["ring_duration"]),
            str(cfg["ring_files"]),
            cfg["tshark_path"],
        ])

    def stop_capture(self) -> None:
        if self.capture_process and self.capture_process.poll() is None:
            self._log("INFO", "Stopping TShark capture")
            self.capture_process.terminate()
            try:
                self.capture_process.wait(timeout=5)
            except Exception:
                self.capture_process.kill()

    def start_capture(self) -> bool:
        cfg = self._get_config()

        if not cfg["capture_interface"]:
            msg = "Capture not started: capture_interface is not configured"
            self._log("WARNING", msg)
            self.current_signature = self._build_signature(cfg)
            self.write_agent_status("waiting_for_interface", msg, cfg)
            return False

        output_file = self.capture_dir / "live_tls_capture.pcapng"

        cmd = [
            cfg["tshark_path"],
            "-i", cfg["capture_interface"],
            "-w", str(output_file),
            "-b", f"duration:{cfg['ring_duration']}",
            "-b", f"files:{cfg['ring_files']}",
            "-Q",
        ]

        if cfg["capture_filter"]:
            cmd.extend(["-f", cfg["capture_filter"]])

        self._log("INFO",
            f"Starting TShark | interface={cfg['capture_interface']} | ring_duration={cfg['ring_duration']} | ring_files={cfg['ring_files']}")

        try:
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.current_signature = self._build_signature(cfg)
            msg = f"TShark started successfully | path={cfg['tshark_path']}"
            self._log("INFO", msg)
            self.write_agent_status("running", msg, cfg)
            return True
        except FileNotFoundError:
            msg = f"TShark not found: {cfg['tshark_path']}"
            self._log("ERROR", msg)
            self.write_agent_status("error", msg, cfg)
            return False
        except Exception as e:
            msg = f"Failed to start TShark: {e}"
            self._log("ERROR", msg)
            self.write_agent_status("error", msg, cfg)
            return False

    def restart_capture_from_config(self) -> bool:
        self.stop_capture()
        time.sleep(1)
        return self.start_capture()

    def watch_for_config_changes(self) -> None:
        cfg = self._get_config()
        new_sig = self._build_signature(cfg)
        if self.current_signature is None:
            self.current_signature = new_sig
            return
        if new_sig != self.current_signature:
            self._log("INFO", "Config change detected in DB — restarting capture")
            self.restart_capture_from_config()

    def run_forever(self) -> None:
        self._log("INFO", "Host capture agent started")
        self.sync_interfaces_to_file()
        self.start_capture()

        sync_counter = 0

        try:
            while True:
                self.watch_for_config_changes()

                if self.capture_process and self.capture_process.poll() is not None:
                    self._log("WARNING", "TShark exited unexpectedly — retrying")
                    time.sleep(2)
                    self.start_capture()

                sync_counter += 1
                if sync_counter >= 10:
                    self.sync_interfaces_to_file()
                    sync_counter = 0

                time.sleep(2)

        except KeyboardInterrupt:
            self._log("WARNING", "Host capture agent interrupted by user")
        finally:
            self.stop_capture()
            self.write_agent_status("stopped", "Host capture agent stopped", self._get_config())
            self._log("INFO", "Host capture agent stopped")


if __name__ == "__main__":
    HostCaptureAgent().run_forever()
