import threading
import subprocess
import logging
import sys
from app.utils.db_handler import DatabaseManager
from app.sniffer.collector import NetworkSniffer

# Setup professional logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def start_backend():
    """Initializes the database and starts the network sniffer."""
    db = DatabaseManager()
    sniffer = NetworkSniffer(db)
    
    try:
        # Use 'any' for Docker/Linux environments
        sniffer.start(interface="any")
    except PermissionError:
        logging.error("Root/Sudo privileges required for sniffing!")
        sys.exit(1)

def start_frontend():
    """Launches the Streamlit UI as a subprocess."""
    logging.info("Launching Discord-styled UI...")
    subprocess.run(["streamlit", "run", "app/ui/dashboard.py"])

if __name__ == "__main__":
    # Run the sniffer in a background thread
    backend_thread = threading.Thread(target=start_backend, daemon=True)
    backend_thread.start()

    # Run the UI in the main thread
    start_frontend()