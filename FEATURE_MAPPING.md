# Feature Mapping: NF-UNSW-NB15-v3 Training vs Real-time Extraction

## ✅ Training Dataset Features (34 features)

Your XGBoost model was trained on these 34 features after preprocessing:

| # | Feature Name | Scapy Extractable | Method |
|---|-------------|-------------------|--------|
| 1 | FLOW_START_MILLISECONDS | ✅ Yes | `pkt.time * 1000` on first packet |
| 2 | IN_BYTES | ✅ Yes | Sum of packet lengths (server → client) |
| 3 | IN_PKTS | ✅ Yes | Count packets (server → client) |
| 4 | OUT_BYTES | ✅ Yes | Sum of packet lengths (client → server) |
| 5 | TCP_FLAGS | ✅ Yes | Bitwise OR of all `pkt[TCP].flags` |
| 6 | FLOW_DURATION_MILLISECONDS | ✅ Yes | `(last_pkt.time - first_pkt.time) * 1000` |
| 7 | DURATION_OUT | ✅ Yes | Duration of outgoing packets |
| 8 | MIN_TTL | ✅ Yes | `min(pkt[IP].ttl)` across flow |
| 9 | LONGEST_FLOW_PKT | ✅ Yes | `max(len(pkt))` |
| 10 | SHORTEST_FLOW_PKT | ✅ Yes | `min(len(pkt))` |
| 11 | MIN_IP_PKT_LEN | ✅ Yes | `min(pkt[IP].len)` |
| 12 | SRC_TO_DST_SECOND_BYTES | ✅ Yes | `OUT_BYTES / duration_seconds` |
| 13 | DST_TO_SRC_SECOND_BYTES | ✅ Yes | `IN_BYTES / duration_seconds` |
| 14 | SRC_TO_DST_AVG_THROUGHPUT | ✅ Yes | Same as `SRC_TO_DST_SECOND_BYTES` |
| 15 | NUM_PKTS_UP_TO_128_BYTES | ✅ Yes | Count packets with `len(pkt) <= 128` |
| 16 | NUM_PKTS_128_TO_256_BYTES | ✅ Yes | Count packets with `128 < len(pkt) <= 256` |
| 17 | NUM_PKTS_256_TO_512_BYTES | ✅ Yes | Count packets with `256 < len(pkt) <= 512` |
| 18 | NUM_PKTS_512_TO_1024_BYTES | ✅ Yes | Count packets with `512 < len(pkt) <= 1024` |
| 19 | NUM_PKTS_1024_TO_1514_BYTES | ✅ Yes | Count packets with `1024 < len(pkt) <= 1514` |
| 20 | TCP_WIN_MAX_IN | ✅ Yes | `max(pkt[TCP].window)` for incoming |
| 21 | TCP_WIN_MAX_OUT | ✅ Yes | `max(pkt[TCP].window)` for outgoing |
| 22 | ICMP_TYPE | ✅ Yes | `pkt[ICMP].type` |
| 23 | DNS_QUERY_ID | ✅ Yes | `pkt[DNS].id` |
| 24 | DNS_QUERY_TYPE | ✅ Yes | `pkt[DNS].qd.qtype` |
| 25 | DNS_TTL_ANSWER | ✅ Yes | `pkt[DNS].an.ttl` |
| 26 | FTP_COMMAND_RET_CODE | ⚠️ Partial | Parse from `pkt[Raw].load` (port 21) |
| 27 | SRC_TO_DST_IAT_MIN | ✅ Yes | `min(iat_list)` for outgoing packets |
| 28 | SRC_TO_DST_IAT_MAX | ✅ Yes | `max(iat_list)` for outgoing packets |
| 29 | SRC_TO_DST_IAT_AVG | ✅ Yes | `mean(iat_list)` for outgoing packets |
| 30 | SRC_TO_DST_IAT_STDDEV | ✅ Yes | `std(iat_list)` for outgoing packets |
| 31 | DST_TO_SRC_IAT_MIN | ✅ Yes | `min(iat_list)` for incoming packets |
| 32 | DST_TO_SRC_IAT_MAX | ✅ Yes | `max(iat_list)` for incoming packets |
| 33 | DST_TO_SRC_IAT_AVG | ✅ Yes | `mean(iat_list)` for incoming packets |
| 34 | DST_TO_SRC_IAT_STDDEV | ✅ Yes | `std(iat_list)` for incoming packets |

---

## ❌ Features REMOVED During Preprocessing (Not needed for real-time)

These features were excluded during your preprocessing step (see cell 9 in notebook):

| Feature | Why Removed | Impact on Real-time |
|---------|-------------|---------------------|
| IPV4_SRC_ADDR | ID/identifying feature | Not needed for prediction |
| IPV4_DST_ADDR | ID/identifying feature | Not needed for prediction |
| L4_SRC_PORT | ID/identifying feature | Not needed for prediction |
| L4_DST_PORT | ID/identifying feature | Not needed for prediction |
| PROTOCOL | ID/identifying feature | Not needed for prediction |
| L7_PROTO | Removed (DPI required) | **Good news:** You don't need nDPI! |
| OUT_PKTS | High correlation (>0.95) | Redundant with other features |
| FLOW_END_MILLISECONDS | Derived from start + duration | Redundant |
| MAX_TTL | High correlation | Redundant |
| MAX_IP_PKT_LEN | High correlation | Redundant |
| DST_TO_SRC_AVG_THROUGHPUT | High correlation | Redundant |
| RETRANSMITTED_IN_BYTES | Low variance or correlation | Not significant |
| RETRANSMITTED_IN_PKTS | Low variance or correlation | Not significant |
| RETRANSMITTED_OUT_BYTES | Low variance or correlation | Not significant |
| RETRANSMITTED_OUT_PKTS | Low variance or correlation | Not significant |
| ICMP_IPV4_TYPE | Duplicate of ICMP_TYPE | Redundant |
| CLIENT_TCP_FLAGS | High correlation | Redundant |
| SERVER_TCP_FLAGS | High correlation | Redundant |
| DURATION_IN | Correlation | Redundant |

---

## 🎯 Real-time Pipeline Feature Coverage

### **Summary:**
- **Total features in training set:** 34
- **Features extractable with Scapy:** 33 (97%)
- **Features requiring approximation:** 1 (FTP_COMMAND_RET_CODE)

### **Extraction Confidence:**
- ✅ **High confidence (33 features):** Direct Scapy extraction or simple aggregation
- ⚠️ **Medium confidence (1 feature):** FTP_COMMAND_RET_CODE (requires payload parsing)

---

## 📋 Feature Order for Model Input

**CRITICAL:** When creating the feature vector for XGBoost prediction, ensure features are ordered EXACTLY as in `feature_names.json`:

```python
FEATURE_ORDER = [
    "FLOW_START_MILLISECONDS",
    "IN_BYTES",
    "IN_PKTS",
    "OUT_BYTES",
    "TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
    "DURATION_OUT",
    "MIN_TTL",
    "LONGEST_FLOW_PKT",
    "SHORTEST_FLOW_PKT",
    "MIN_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES",
    "DST_TO_SRC_SECOND_BYTES",
    "SRC_TO_DST_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES",
    "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES",
    "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT",
    "ICMP_TYPE",
    "DNS_QUERY_ID",
    "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER",
    "FTP_COMMAND_RET_CODE",
    "SRC_TO_DST_IAT_MIN",
    "SRC_TO_DST_IAT_MAX",
    "SRC_TO_DST_IAT_AVG",
    "SRC_TO_DST_IAT_STDDEV",
    "DST_TO_SRC_IAT_MIN",
    "DST_TO_SRC_IAT_MAX",
    "DST_TO_SRC_IAT_AVG",
    "DST_TO_SRC_IAT_STDDEV"
]
```

---

## 🚀 Integration Steps

1. **Capture packets** using Scapy
2. **Aggregate into flows** using `FlowAggregator` class
3. **Export features** when flow completes (timeout or FIN/RST)
4. **Order features** according to `FEATURE_ORDER`
5. **Scale features** using `scaler_binary.pkl` or `scaler_multiclass.pkl`
6. **Predict** using `xgboost_binary.pkl` → then `xgboost_multiclass.pkl` if attack detected

---

## ⚠️ Important Notes

### **Flow Timeout**
- Recommended: **30 seconds** of inactivity
- Adjust based on network characteristics

### **Missing Features (Default Values)**
- If a flow doesn't have ICMP packets: `ICMP_TYPE = 0`
- If no DNS queries: `DNS_QUERY_ID = 0`, `DNS_QUERY_TYPE = 0`, `DNS_TTL_ANSWER = 0`
- If not FTP: `FTP_COMMAND_RET_CODE = 0`

### **Bidirectional Flow Tracking**
- Always use **normalized 5-tuple** to match bidirectional flows
- Example: (192.168.1.1:45000, 8.8.8.8:53, UDP) and (8.8.8.8:53, 192.168.1.1:45000, UDP) should be the SAME flow

### **Memory Management**
- Set `max_flows` limit to prevent memory exhaustion
- Periodically cleanup expired flows (every 100-1000 packets)

---

## ✅ Verification Checklist

Before deploying:

- [ ] Feature names match exactly (case-sensitive)
- [ ] Feature order matches `feature_names.json`
- [ ] All 34 features are present in output dictionary
- [ ] Features are scaled using the correct scaler
- [ ] Flow timeout is configured appropriately
- [ ] Bidirectional flow tracking is working
- [ ] TCP retransmission detection is accurate (optional, as removed in training)
- [ ] IAT statistics are computed correctly

---

**Author:** RASSYIDZ - UniKL MIIT FYP
**Dataset:** NF-UNSW-NB15-v3
**Model:** XGBoost Binary + Multi-class
