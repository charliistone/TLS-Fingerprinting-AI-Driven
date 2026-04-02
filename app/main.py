import threading
import subprocess
import logging
import sys
import os
from app.utils.db_handler import DatabaseManager
from app.sniffer.collector import NetworkSniffer
from app.models.predictor import TLSPredictor

# Setup professional logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

def start_backend():
    db = DatabaseManager()
    predictor = TLSPredictor() # Load the AI
    sniffer = NetworkSniffer(db, predictor) # Inject both DB and AI
    sniffer.start(interface="any")
    
    try:
        # Use 'any' for Docker/Linux environments
        sniffer.start(interface="any")
    except PermissionError:
        logging.error("Root/Sudo privileges required for sniffing!")
        sys.exit(1)

def start_frontend():
    """Launches the Streamlit UI as a subprocess."""
    logging.info("Launching UI...")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    
    # Use streamlit that inside the venv
    streamlit_path = os.path.join(os.getcwd(), "venv", "bin", "streamlit")
    
    subprocess.run([streamlit_path, "run", "app/ui/dashboard.py"], env=env)

if __name__ == "__main__":
    # Run the sniffer in a background thread
    backend_thread = threading.Thread(target=start_backend, daemon=True)
    backend_thread.start()

    # Run the UI in the main thread
    start_frontend()