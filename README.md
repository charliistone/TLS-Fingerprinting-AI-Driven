# AI-Driven TLS Fingerprinting & Threat Intelligence Framework

![Python](https://img.shields.io/badge/Python-3.10-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Enabled-blue.svg)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-blue.svg)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Overview
As encryption standards like **TLS 1.3** become the global norm, traditional Deep Packet Inspection (DPI) is becoming obsolete. This project provides a sophisticated network security framework designed to classify and analyze encrypted traffic **without decryption**. 

By leveraging **JA3/JA3S Fingerprinting**, Machine Learning, and a real-time **Active Verification** loop, the system detects malicious patterns such as Command & Control (C2) communication, malware delivery, and phishing attempts.

> **Thesis Project:** This system is developed as a Senior Design Project (Bachelor's Thesis) at Ankara Bilim University, focusing on the intersection of Network Security and Cloud-Native AI Orchestration.

---

## Key Features
* **Cloud-Native & Scalable:** Fully Dockerized architecture, designed for seamless orchestration via **Kubernetes (K8s)**.
* **High-Performance Sniffing:** Real-time packet capture utilizing `Scapy` and `TShark` within optimized Linux containers using **Host Network** access.
* **JA3/JA3S Profiling:** Automated extraction of TLS handshake metadata to create unique cryptographic signatures.
* **AI-Powered Classification:** Multi-layered Machine Learning models for anomaly detection and malware family classification.
* **Active Verification (Feedback Loop):** An innovative module that validates "suspicious" fingerprints against global Threat Intelligence (TI) feeds (e.g., **Abuse.ch SSLBL**, **VirusTotal**).

---

## System Architecture
The system operates as a continuous, asynchronous pipeline:

1.  **Capture Layer:** Ingests raw network traffic via Host Network access.
2.  **Processing Layer:** Extracts TLS features and calculates JA3/JA3S hashes.
3.  **Inference Layer:** The AI model predicts the nature of the traffic (Benign vs. Malicious).
4.  **Verification Layer:** High-confidence threats are cross-referenced with external TI APIs.
5.  **Persistence Layer:** All findings are stored in **PostgreSQL** for forensic analysis and future model retraining.

---

## Tech Stack
| Category | Technology |
| :--- | :--- |
| **Programming** | Python 3.10+ |
| **Containerization** | Docker, Docker Compose |
| **Orchestration** | Kubernetes (Deployment, Secrets, ConfigMaps) |
| **Network Analysis** | TShark, Scapy |
| **Data & AI** | Pandas, Scikit-learn, NumPy |
| **Database** | PostgreSQL |

---

## Project Structure
tls-fingerprinting/
├── app/                    # Core Application Logic
│   ├── main.py             # Main Orchestrator
│   ├── sniffer/            # Packet Capture & Sniffing Logic
│   ├── processing/         # JA3 Extraction & Feature Engineering
│   ├── models/             # ML Model Inference Engine
│   └── utils/              # Active Verifier & DB Handlers
├── k8s/                    # Kubernetes Deployment Manifests
├── data/                   # Local PCAP & Dataset Storage
├── saved_models/           # Pre-trained Model Weights (.pkl)
├── Dockerfile              # Multi-stage Optimized Build
├── docker-compose.yml      # Local Multi-container Orchestration
└── requirements.txt        # Python Dependencies

---
---
---

## Getting Started

### Prerequisites
* **Docker & Docker Compose** installed.
* **Root/Administrator privileges** (required for raw socket access/sniffing).
* (Optional) **Minikube** or **Kind** for Kubernetes orchestration.

### Local Deployment (Docker)
1. **Clone the repository:**
    git clone [https://github.com/AhmetCanCengiz/TLS-Project.git](https://github.com/AhmetCanCengiz/TLS-Project.git)
    cd TLS-Project

2. **Start the entire stack (App + Database):**
    docker-compose up --build
    
   *The system will automatically start sniffing on the host network and log findings to the PostgreSQL container.*

### Kubernetes Deployment
Deploy the infrastructure to a K8s cluster:
    kubectl apply -f k8s/configmap.yaml
    kubectl apply -f k8s/secret.yaml
    kubectl apply -f k8s/deployment.yaml

---

## Active Verification Loop
One of the standout features of this project is the **Active Verification** mechanism. Unlike static analysis tools, this system:
* **Flags** a suspicious JA3 hash via the ML model.
* **Automatically queries** global databases (**Abuse.ch SSLBL**).
* **Updates** its own database with a "Verified Malicious" tag if a match is found.
* This creates a self-improving feedback loop for the security analyst.

---

## ⚠️ Disclaimer
This project is developed for academic and research purposes only. The tools provided here should be used only on networks where you have explicit permission to monitor traffic. The author assumes no responsibility for misuse or unauthorized network monitoring.

---

## Author
**Ahmet Can Cengiz** Computer Engineering Student at **Ankara Bilim University** *Expected Graduation: Summer 2026* [LinkedIn](https://www.linkedin.com/in/ahmet-can-cengiz-61a58a2a2/) | [GitHub](https://github.com/charliistone)
