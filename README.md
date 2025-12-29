
# AI-Driven TLS Fingerprinting & Threat Analysis System

  

**An advanced network security framework designed to detect anomalies in encrypted traffic using TLS Fingerprinting (JA3/JA3S), Machine Learning, and Active Verification techniques.**

  

>  **Status:** Active Development (Data Collection & Pipeline Phase)

>  **Type:** Senior Design Project (Bachelor's Thesis)

  

---

  

## 📖 Overview

  

As encryption standards (TLS 1.3) become ubiquitous, traditional Deep Packet Inspection (DPI) loses its effectiveness. This project aims to classify and analyze malicious traffic **without decryption** by leveraging **TLS Fingerprinting (JA3)** methods.

  

The system autonomously captures network traffic, extracts TLS handshake metadata, calculates unique fingerprints, and prepares datasets for Machine Learning models to detect C2 servers, malware, and phishing attempts.

  

### Key Features

-  **🚀 Automated Data Pipeline:** Real-time traffic capture (Ring Buffer) and automated processing.

-  **🔍 JA3/JA3S Fingerprinting:** Extracts and calculates MD5 hashes from ClientHello packets.

-  **📊 Dataset Generation:** Automatically builds CSV datasets suitable for AI/ML training.

-  **🛡️ Active Verification (Planned):** A feedback loop mechanism to verify suspicious fingerprints against external threat intelligence.

  

---

  

## 📂 Project Structure

  

```bash

TLS-Project/

├── src/

│ ├── capture/ # PowerShell scripts for TShark automation & workflow management

│ └── processing/ # Python modules for JA3 extraction & data cleaning

├── data/

│ ├── raw_pcaps/ # Temporary storage for captured PCAP files (Not synced to Git)

│ ├── processed_csvs/ # Generated datasets (Master CSVs)

│ └── logs/ # Operational logs for debugging

├── docs/ # Survey papers and architectural diagrams

└── requirements.txt # Python dependencies

```
## ⚙️ Prerequisites

To run this system, ensure you have the following installed:

Wireshark & TShark:

Must be installed with the TShark component selected.

Crucial: The Wireshark folder (e.g., C:\Program Files\Wireshark) must be added to your system's PATH environment variable.

Python 3.x:

Required for parsing and feature extraction.

PowerShell:

Required for running the automation scripts (Admin privileges recommended for capturing).

  

## Installation

Clone the repository and install Python dependencies:

git clone [https://github.com/YOUR_USERNAME/TLS-Project.git](https://github.com/YOUR_USERNAME/TLS-Project.git)

cd TLS-Project

pip install -r requirements.txt


## 💻 Usage

The system operates using two parallel processes: Capture and Watcher.

  

1. Start Traffic Capture

This script captures network packets in a ring-buffer format. It will ask you to select the network interface.
```bash

cd src/capture

.\capture.ps1
```
### Select your active network interface (e.g., Ethernet or Wi-Fi) from the list.


2. Start the Watcher (Processor)

Open a new terminal window. This script monitors the capture folder. When a PCAP file is closed, it triggers the Python extractor, updates the dataset, and cleans up the raw file.

```bash

cd src/capture

.\watcher.ps1

```
⚠️ Disclaimer

This project is developed for academic and research purposes only. The tools provided here should be used only on networks where you have explicit permission to monitor traffic. The author assumes no responsibility for misuse.