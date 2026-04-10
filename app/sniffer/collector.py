import logging
import os
import shutil
import subprocess
from typing import Optional


class TSharkLiveCaptureAgent:
    """
    Manages a live TShark capture subprocess for ring-buffer PCAP generation.
    Replaces the scapy-based sniffer with a tshark subprocess approach.
    Used by TLSFingerprintPipeline for continuous live capture.
    """

    def __init__(
        self,
        capture_dir: str = "data/captures",
        tshark_path: Optional[str] = None,
        interface: Optional[str] = None,
        capture_filter: Optional[str] = None,
        ring_duration: int = 30,
        ring_files: int = 10,
    ):
        self.capture_dir = capture_dir
        self.tshark_path = tshark_path or self._resolve_tshark()
        self.interface = interface or ""
        self.capture_filter = capture_filter or ""
        self.ring_duration = ring_duration
        self.ring_files = ring_files
        self.process: Optional[subprocess.Popen] = None

    @staticmethod
    def _resolve_tshark() -> str:
        return (
            os.environ.get("TSHARK_PATH")
            or shutil.which("tshark")
            or r"C:\Program Files\Wireshark\tshark.exe"
        )

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self) -> bool:
        """Start a TShark ring-buffer capture. Returns True on success."""
        if not self.interface:
            logging.warning("[sniffer] No interface configured — live capture not started.")
            return False

        output_file = os.path.join(self.capture_dir, "live_tls_capture.pcapng")
        os.makedirs(self.capture_dir, exist_ok=True)

        cmd = [
            self.tshark_path,
            "-i", self.interface,
            "-w", output_file,
            "-b", f"duration:{self.ring_duration}",
            "-b", f"files:{self.ring_files}",
            "-Q",
        ]
        if self.capture_filter:
            cmd.extend(["-f", self.capture_filter])

        logging.info(
            "[sniffer] Starting TShark | interface=%s | ring_duration=%s | ring_files=%s",
            self.interface, self.ring_duration, self.ring_files
        )

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            logging.info("[sniffer] TShark process started (pid=%s)", self.process.pid)
            return True
        except FileNotFoundError:
            logging.error("[sniffer] TShark not found at: %s", self.tshark_path)
            return False
        except Exception as e:
            logging.error("[sniffer] Failed to start TShark: %s", e)
            return False

    def stop(self) -> None:
        """Terminate the TShark capture process gracefully."""
        if self.process and self.process.poll() is None:
            logging.info("[sniffer] Stopping TShark capture (pid=%s)", self.process.pid)
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()
            self.process = None