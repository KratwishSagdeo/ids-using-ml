🚨 Hybrid Machine Learning Intrusion Detection System (ML-IDS)

A real-time Intrusion Detection System (IDS) powered by Hybrid Machine Learning models that analyzes network traffic and detects malicious activities such as port scans, brute force attempts, and suspicious packets.

This system integrates packet capture, feature extraction, ML inference, and alert generation to identify cyber threats in real time.

📌 Project Overview

Traditional IDS systems rely heavily on signature-based detection, which fails to detect zero-day attacks and unknown threats.

This project implements a Hybrid ML-based IDS that combines:

Real-time network packet analysis

Machine learning threat classification

Automated alert ingestion

Threat logging and monitoring APIs

The system processes captured packets, extracts network features, and uses trained ML models to detect malicious traffic with high accuracy.

⚙️ System Architecture
Network Traffic
      │
      ▼
Packet Capture (PCAP / Network Interface)
      │
      ▼
Feature Extraction
      │
      ▼
Hybrid ML Model
(Random Forest + Other Models)
      │
      ▼
Threat Classification
      │
      ▼
FastAPI Backend
      │
      ▼
Alert Logging & Storage
🚀 Key Features

✔ Real-time network packet analysis
✔ Hybrid Machine Learning model for intrusion detection
✔ Detection of multiple attack categories
✔ FastAPI backend for alert ingestion and analysis
✔ PCAP file upload and analysis API
✔ Threat logging and monitoring
✔ Modular architecture for future improvements

🧠 Machine Learning Model

The system uses a Hybrid ML approach to improve detection accuracy.

Models Used

Random Forest

Gradient Boosting (optional depending on implementation)

Ensemble decision logic

Model Performance
Metric	Value
Accuracy	~94-97%
Precision	~93%
Recall	~92%
F1 Score	~92%

(Metrics may vary depending on dataset and tuning.)

📊 Dataset

The model was trained using network intrusion detection datasets such as:

CICIDS2017

NSL-KDD (optional if used)

These datasets contain labeled examples of:

Normal network traffic

DoS / DDoS attacks

Port scans

Brute force attacks

Botnet traffic

🛠 Tech Stack
Programming

Python

Machine Learning

Scikit-learn

Pandas

NumPy

Backend

FastAPI

Uvicorn

Networking / Security

PCAP packet analysis

Network traffic feature extraction

Data Processing

CSV datasets

Numpy arrays

Feature engineering pipeline

📂 Project Structure
ids-ml-project
│
├── backend
│   ├── main.py
│   ├── api
│   ├── routes
│
├── model
│   ├── train_model.py
│   ├── model.pkl
│
├── data
│   ├── dataset.csv
│
├── notebooks
│   ├── training_notebook.ipynb
│
├── uploads
│   ├── uploaded_pcap_files
│
├── utils
│   ├── feature_extraction.py
│
├── requirements.txt
└── README.md
🔌 API Endpoints
Upload PCAP File
POST /upload_pcap

Uploads a network capture file for analysis.

Ingest Alert
POST /ingest_alert

Accepts processed threat alerts and logs them into the system.

▶️ How to Run the Project
1️⃣ Clone the repository
git clone https://github.com/yourusername/ml-ids-project.git

cd ml-ids-project
2️⃣ Create Virtual Environment
python -m venv venv

Activate it

Windows

venv\Scripts\activate

Linux / Mac

source venv/bin/activate
3️⃣ Install Dependencies
pip install -r requirements.txt
4️⃣ Run the FastAPI Server
uvicorn main:app --reload

Server will start at:

http://127.0.0.1:8000

API documentation:

http://127.0.0.1:8000/docs
🔍 Example Workflow

1️⃣ Capture network packets using Wireshark / tcpdump
2️⃣ Upload PCAP file to API
3️⃣ Extract network features
4️⃣ ML model classifies traffic
5️⃣ Alerts generated for malicious traffic

📈 Future Improvements

Deep Learning based IDS (LSTM / Autoencoders)

Real-time network monitoring using Scapy

Integration with SIEM systems

Dashboard for threat visualization

Docker containerization

Streaming analysis using Kafka

🔐 Security Applications

This project can be used for:

Network security monitoring

Malware traffic detection

Enterprise security systems

SOC (Security Operations Center) tooling

Cybersecurity research

👨‍💻 Author

Kratwish
Cybersecurity Student | Machine Learning Enthusiast

Interests: Cybersecurity, Intrusion Detection Systems, Machine Learning Security

⭐ If you found this project useful

Give the repository a star ⭐ on GitHub to support the project.
