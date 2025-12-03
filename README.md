# Real-time Network Intrusion Detection System (NIDS)

**Author:** RASSYIDZ - UniKL MIIT FYP
**Dataset:** NF-UNSW-NB15-v3 (2.3M flows, 10 attack classes)
**Model:** XGBoost Binary + Multi-class
**Accuracy:** 99.99% (Binary), 98.69% (Multi-class)

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Features](#features)
4. [Installation](#installation)
5. [Usage](#usage)
6. [File Structure](#file-structure)
7. [Feature Extraction Details](#feature-extraction-details)
8. [Performance](#performance)
9. [Troubleshooting](#troubleshooting)

---

## 🔍 Overview

This real-time NIDS captures network traffic using Scapy, aggregates packets into flows, extracts 34 NetFlow features matching the NF-UNSW-NB15-v3 dataset, and uses XGBoost models for two-stage threat detection:

1. **Binary Classification:** Benign vs Attack (99.99% accuracy)
2. **Multi-class Classification:** 10 attack types (98.69% accuracy)

### Attack Types Detected:
- Analysis
- Backdoor
- DoS (Denial of Service)
- Exploits
- Fuzzers
- Generic
- Reconnaissance
- Shellcode
- Worms

---

## 🏗️ Architecture

```
┌──────────────────┐
│  Network Traffic │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────┐
│  Scapy Packet Capture    │
│  (realtime_nids.py)      │
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────────┐
│  Flow Aggregator         │
│  (flow_aggregator.py)    │
│  - 5-tuple tracking      │
│  - Feature computation   │
│  - Timeout management    │
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────────┐
│  Feature Extraction      │
│  34 NF-UNSW-NB15-v3      │
│  features                │
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────────┐
│  XGBoost Binary Model    │
│  (Benign vs Attack)      │
└────────┬─────────────────┘
         │
         ├─ Benign ───────────────┐
         │                        │
         ├─ Attack                │
         ▼                        ▼
┌──────────────────────────┐   ┌─────────┐
│  XGBoost Multi-class     │   │  SAFE   │
│  (Attack Type)           │   └─────────┘
└────────┬─────────────────┘
         │
         ▼
┌──────────────────────────┐
│  🚨 ALERT                │
│  Attack Type + Confidence│
└──────────────────────────┘
```

---

## ✨ Features

### Real-time Capabilities:
- ✅ Live packet capture from network interface
- ✅ Offline PCAP file analysis
- ✅ Bidirectional flow tracking
- ✅ Automatic flow timeout (30s default)
- ✅ Memory-efficient (max 100k concurrent flows)

### Feature Extraction (34 features):
- ✅ **Direct capture:** IP addresses, ports, TTL, TCP flags, window size, ICMP, DNS
- ✅ **Aggregation:** Byte/packet counters, flow duration, throughput
- ✅ **Statistics:** IAT (Inter-Arrival Time) min/max/avg/stddev
- ✅ **Distribution:** Packet size bins (5 bins)
- ✅ **TCP Analysis:** Retransmission detection (sequence numbers)

### Detection:
- ✅ Two-stage classification (binary → multi-class)
- ✅ Confidence scoring
- ✅ Real-time alerts
- ✅ Attack type breakdown

---

## 📦 Installation

### Requirements:
```bash
pip install scapy numpy pandas scikit-learn xgboost joblib imbalanced-learn
```

### On Windows (Administrator required):
```bash
# Install Npcap for packet capture
# Download from: https://npcap.com/
```

### On Linux:
```bash
sudo apt-get install python3-pip tcpdump
pip install scapy numpy pandas scikit-learn xgboost joblib
```

---

## 🚀 Usage

### 1. Live Capture (Administrator/Root required)

```bash
# Capture on default interface
python realtime_nids.py

# Capture on specific interface
python realtime_nids.py -i eth0

# Capture limited packets
python realtime_nids.py -c 10000
```

### 2. Offline PCAP Analysis

```bash
# Analyze PCAP file
python realtime_nids.py -r /path/to/capture.pcap

# Analyze with custom model directory
python realtime_nids.py -r capture.pcap -m ./models/model_files/
```

### 3. Integration Example

```python
from realtime_nids import RealtimeNIDS

# Initialize NIDS
nids = RealtimeNIDS(model_dir="./models/model_files/")

# Start live capture
nids.start_capture(interface="eth0")

# Or analyze PCAP
nids.start_capture(pcap_file="traffic.pcap")
```

### 4. Using Flow Aggregator Directly

```python
from flow_aggregator import FlowAggregator
from scapy.all import sniff

# Initialize aggregator
aggregator = FlowAggregator(flow_timeout=30)

# Process packets
def packet_handler(pkt):
    aggregator.process_packet(pkt)

    # Get completed flows
    if aggregator.get_active_flow_count() % 100 == 0:
        completed = aggregator.cleanup_old_flows()
        for flow_features in completed:
            print(flow_features)

sniff(prn=packet_handler, store=False)
```

---

## 📁 File Structure

```
nids_system/
├── flow_aggregator.py          # Flow tracking & feature extraction
├── realtime_nids.py             # Main NIDS application
├── FEATURE_MAPPING.md           # Feature documentation
├── README_REALTIME_NIDS.md      # This file
│
└── models/model_files/
    ├── xgboost_binary.pkl       # Binary classifier
    ├── xgboost_multiclass.pkl   # Multi-class classifier
    ├── scaler_binary.pkl        # Binary feature scaler
    ├── scaler_multiclass.pkl    # Multi-class feature scaler
    ├── label_encoder_multiclass.pkl  # Attack type encoder
    └── feature_names.json       # Feature order (34 features)
```

---

## 🔬 Feature Extraction Details

### Flow Identification (5-tuple):
```python
(source_ip, destination_ip, source_port, destination_port, protocol)
```

### Feature Categories:

#### 1. Direct Packet Features (Scapy)
- **IP Layer:** `pkt[IP].src`, `pkt[IP].dst`, `pkt[IP].ttl`, `pkt[IP].len`
- **Transport Layer:** `pkt[TCP].sport`, `pkt[TCP].dport`, `pkt[TCP].flags`, `pkt[TCP].window`
- **Application Layer:** `pkt[DNS].id`, `pkt[ICMP].type`

#### 2. Flow Aggregation Features
- **Counters:** IN_BYTES, OUT_BYTES, IN_PKTS, OUT_PKTS
- **Timing:** FLOW_START, FLOW_DURATION
- **Size Stats:** MIN/MAX packet lengths, size bins

#### 3. Statistical Features
- **IAT (Inter-Arrival Time):**
  - Tracked separately for each direction (src→dst, dst→src)
  - Computed: MIN, MAX, AVG, STDDEV
  - Unit: milliseconds

#### 4. TCP Advanced Features
- **Retransmission Detection:** Track duplicate sequence numbers
- **Window Analysis:** Track maximum TCP window size

### Feature Computation Example:

```python
# IAT calculation
if current_direction == "outgoing":
    if last_out_time is not None:
        iat_ms = (packet_time - last_out_time) * 1000
        iat_out_list.append(iat_ms)
    last_out_time = packet_time

# Statistics
SRC_TO_DST_IAT_MIN = min(iat_out_list)
SRC_TO_DST_IAT_MAX = max(iat_out_list)
SRC_TO_DST_IAT_AVG = mean(iat_out_list)
SRC_TO_DST_IAT_STDDEV = std(iat_out_list)
```

---

## 📊 Performance

### Model Performance (from training):
| Model | Task | Accuracy | F1-Score | Time |
|-------|------|----------|----------|------|
| XGBoost | Binary | 99.99% | 99.96% | 13.6s |
| XGBoost | Multi-class | 98.69% | 98.74% | 516s |

### Real-time Performance:
- **Throughput:** ~1000-5000 packets/second (depends on hardware)
- **Latency:** <1ms per packet (aggregation only)
- **Memory:** ~100 bytes per active flow
- **Flow timeout:** 30 seconds (configurable)

### Tested Environments:
- ✅ Windows 10/11 (Npcap required)
- ✅ Linux Ubuntu 20.04/22.04
- ✅ Python 3.8-3.11

---

## 🔧 Configuration

### Adjust Flow Timeout:
```python
# Default: 30 seconds
aggregator = FlowAggregator(flow_timeout=60)  # 60 seconds
```

### Adjust Max Concurrent Flows:
```python
# Default: 100,000 flows
aggregator = FlowAggregator(max_flows=50000)
```

### Custom Feature Selection:
```python
# Load feature names from JSON
with open('feature_names.json', 'r') as f:
    features = json.load(f)

# Modify as needed (must match training features!)
```

---

## ⚠️ Important Notes

### 1. Feature Order Matters!
The features **MUST** be in the exact order as `feature_names.json`. The model expects features in this specific order.

### 2. Bidirectional Flow Tracking
Flows are tracked bidirectionally. A packet from A→B and B→A belong to the **same flow**.

### 3. Flow Timeout
- Flows expire after 30 seconds of inactivity (default)
- Adjust based on your network (longer for slow connections)

### 4. Missing Protocol Features
- If flow has no DNS packets: `DNS_QUERY_ID = 0`, `DNS_QUERY_TYPE = 0`
- If flow has no ICMP: `ICMP_TYPE = 0`
- Default to 0 for missing protocol-specific features

### 5. Scaling
Features are automatically scaled using the loaded scalers. **Do not** manually scale features.

---

## 🐛 Troubleshooting

### Problem: "No packets captured"
**Solution:**
- Run with Administrator/root privileges
- Check interface name (`ip addr` or `ipconfig`)
- Install Npcap (Windows) or libpcap (Linux)

### Problem: "ModuleNotFoundError: No module named 'scapy'"
**Solution:**
```bash
pip install scapy
```

### Problem: "Model file not found"
**Solution:**
- Ensure model files are in `./models/model_files/`
- Or specify custom path: `-m /path/to/models/`

### Problem: "Feature dimension mismatch"
**Solution:**
- Verify `feature_names.json` has exactly 34 features
- Check that `flow_aggregator.export_features()` returns all 34 features
- Ensure no extra features are added

### Problem: High false positive rate
**Solution:**
- This is expected if your network traffic differs from NF-UNSW-NB15-v3
- Consider re-training with your network's benign traffic
- Adjust confidence threshold if needed

---

## 📝 Example Output

```
[*] Initializing NIDS - 2025-12-02 14:30:00
[✓] Loaded binary model: XGBoost
[✓] Loaded multi-class model: XGBoost
[✓] Features: 34
[✓] Attack classes: 10
[✓] NIDS ready for packet capture

[*] Starting live packet capture...
[*] Press Ctrl+C to stop

================================================================================
🚨 ATTACK DETECTED - 2025-12-02 14:35:12
================================================================================
  Type: Reconnaissance
  Confidence: 92.45%
  Attack Probability: 98.73%

  Flow Details:
    Duration: 15234 ms
    Packets: IN=42, OUT=38
    Bytes: IN=5432, OUT=4231
    TCP Flags: 18
================================================================================

────────────────────────────────────────────────────────────────────────────────
📊 NIDS Statistics - 14:40:00
────────────────────────────────────────────────────────────────────────────────
  Packets Processed: 50,000
  Flows Completed: 1,234
  Active Flows: 87
  Benign: 1,198 (97.1%)
  Attacks: 36 (2.9%)

  Attack Breakdown:
    Reconnaissance: 18
    Exploits: 12
    DoS: 4
    Generic: 2
────────────────────────────────────────────────────────────────────────────────
```

---

## 📚 References

- **Dataset:** NF-UNSW-NB15-v3 ([Paper](https://research.unsw.edu.au/projects/unsw-nb15-dataset))
- **Scapy Documentation:** https://scapy.readthedocs.io/
- **XGBoost:** https://xgboost.readthedocs.io/

---

## 🎓 Academic Use

This project is part of a Final Year Project (FYP) at UniKL MIIT.

**Citation:**
```
RASSYIDZ (2024-2025)
Enhanced Predictive Classification of Cybersecurity Threats
Final Year Project, Universiti Kuala Lumpur (UniKL MIIT)
Semester 6, 2024/2025
```

---

## 📄 License

For educational and research purposes only.

---

**Contact:** RASSYIDZ - UniKL MIIT
**Project:** Enhanced Predictive Classification of Cybersecurity Threats
**Status:** ✅ Ready for Deployment
