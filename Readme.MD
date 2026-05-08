# AI-Powered Hybrid Intrusion Detection System (IDS)

An intelligent cybersecurity monitoring system that combines **Machine Learning (ML)** and **Deep Learning (DL)** techniques to detect suspicious network activities, analyze packet traffic, and classify anomalies in real time through an interactive Streamlit dashboard.

---

## 📌 Project Overview

This project focuses on detecting malicious or abnormal network behavior using packet-level traffic analysis.
The system captures or uploads network traffic data (`.pcapng` / `.csv`) and performs:

* Packet inspection
* Feature extraction
* Anomaly detection
* Threat severity analysis
* Real-time monitoring visualization

The application is built using **Python**, **Scapy**, **Pandas**, **Streamlit**, and ML/DL-based detection logic.

---

# 🚀 Features

* ✅ Real-time packet monitoring
* ✅ PCAPNG to CSV conversion
* ✅ Upload custom CSV attack datasets
* ✅ Hybrid ML/DL anomaly detection
* ✅ Threat severity classification
* ✅ Port-based suspicious activity analysis
* ✅ Interactive SOC-style dashboard
* ✅ Safe / Warning / Critical status detection
* ✅ Visualization charts and analytics
* ✅ Attack traffic identification

---

# 🛠️ Technologies Used

| Technology          | Purpose                    |
| ------------------- | -------------------------- |
| Python              | Core programming           |
| Streamlit           | Web dashboard UI           |
| Pandas              | Data preprocessing         |
| NumPy               | Numerical operations       |
| Scapy               | Packet capture and parsing |
| PyShark             | PCAP processing            |
| Matplotlib / Plotly | Visualization              |
| Scikit-learn        | Machine Learning           |
| TensorFlow / Keras  | Deep Learning              |
| Wireshark           | Packet capture             |

---

# 📂 Project Structure

```bash
Mini_Project/
│
├── app.py               # Main Streamlit dashboard
├── main.py              # Core execution script
├── attack.csv           # Sample attack dataset
├── 1.csv                # Sample normal traffic dataset
├── attack.pcapng        # Sample packet capture file
├── requirements.txt     # Required dependencies
├── README.md            # Project documentation
├── .gitignore           # Ignore unnecessary files
└── venv/                # Virtual environment (ignored)
```

---

# ⚙️ Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/Anbuselvi26/Mini_Project.git
cd Mini_Project
```

---

## 2️⃣ Create Virtual Environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / Mac

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Running the Application

## Run Streamlit Dashboard

```bash
streamlit run app.py
```

OR

```bash
python -m streamlit run app.py
```

---

# 🌐 Open in Browser

After running:

```bash
Local URL: http://localhost:8501
```

Open the link in your browser.

---

# 📊 Dataset Input Options

The application supports:

| File Type | Purpose                      |
| --------- | ---------------------------- |
| `.csv`    | Preprocessed traffic dataset |
| `.pcapng` | Raw packet capture traffic   |

---

# 🔄 PCAPNG to CSV Conversion

The system can convert `.pcapng` files into `.csv` format for analysis.

## Example Workflow

1. Capture packets using Wireshark
2. Save file as `.pcapng`
3. Upload `.pcapng` into the application
4. System extracts:

   * Source IP
   * Destination IP
   * Ports
   * Protocols
   * Packet length
   * Packet statistics
5. Converted CSV is analyzed for anomalies

---

# 📦 Manual PCAPNG to CSV Conversion (Optional)

You can also convert packets manually using Python.

## Example

```python
from scapy.all import rdpcap
import pandas as pd

packets = rdpcap("attack.pcapng")

data = []

for pkt in packets:
    if pkt.haslayer("IP"):
        data.append({
            "src_ip": pkt["IP"].src,
            "dst_ip": pkt["IP"].dst,
            "protocol": pkt["IP"].proto,
            "length": len(pkt)
        })

df = pd.DataFrame(data)
df.to_csv("output.csv", index=False)

print("Conversion completed.")
```

---

# 🧠 Detection Logic

The IDS analyzes:

* Packet count anomalies
* Port scanning behavior
* Traffic spikes
* Suspicious protocols
* Malicious communication patterns
* Abnormal packet frequency
* High-risk network activity

---

# 🚨 Threat Severity Levels

| Severity    | Meaning                   |
| ----------- | ------------------------- |
| 🟢 Safe     | Normal traffic            |
| 🟡 Warning  | Suspicious activity       |
| 🔴 Critical | Potential attack detected |

---

# 📈 Dashboard Modules

* Network Traffic Summary
* Packet Statistics
* Threat Severity Banner
* Anomaly Detection Results
* Suspicious Port Analysis
* Live Monitoring Panel
* Upload Dataset Section
* Visualization Graphs

---

# 🧪 Sample Demo Workflow

## Safe Traffic Demo

1. Open Wireshark
2. Start packet capture
3. Browse normal websites
4. Export packets
5. Upload into application
6. Observe Safe status

---

## Suspicious Traffic Demo

1. Run high packet generation activity
2. Simulate abnormal traffic
3. Export capture
4. Upload into application
5. Observe Warning/Critical alerts

---

# 📋 Example Commands

## Ping Flood Test

```bash
ping 127.0.0.1 -t
```

## Port Scan Example

```bash
nmap localhost
```

---

# 🔒 Cybersecurity Concepts Used

* Intrusion Detection System (IDS)
* Anomaly Detection
* Network Traffic Analysis
* Packet Inspection
* Behavioral Analysis
* ML-based Classification
* Deep Learning Security Analytics

---

# 📌 Future Enhancements

* Real-time live packet sniffing
* Advanced DL models
* Explainable AI (XAI)
* Attack type classification
* SOC automation
* Threat intelligence integration
* Cloud deployment

---

# 👩‍💻 Author

**Anbuselvi S**

Mini Project – AI-Based Hybrid Intrusion Detection System

---

# 📄 License

This project is for educational and academic purposes.

---

# 🙌 Acknowledgements

* Wireshark
* Scapy
* Streamlit
* Scikit-learn
* TensorFlow
* Open-source cybersecurity community

---

# 📝 Suggested `.gitignore`

```gitignore
# Virtual Environment
venv/
env/

# Python Cache
__pycache__/
*.pyc

# Jupyter
.ipynb_checkpoints/

# System Files
.DS_Store
Thumbs.db

# Streamlit
.streamlit/

# Logs
*.log

# Temporary Files
*.tmp
```
