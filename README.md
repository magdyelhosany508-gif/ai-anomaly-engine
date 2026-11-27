# 🛡️ Zero-Trust Bio-IoT Sentinel — AI Behavioral Anomaly Engine

Real-time behavioral anomaly detection microservice for Industrial IoT (IIoT) networks using a tuned **Random Forest Classifier** trained on the **CIC IIoT 2025** dataset.

## 📁 Repository Structure
- `main.py`: FastAPI inference microservice exposing `/predict` for real-time risk scoring and 4-tier progressive policy classification (`ALLOW`, `MONITOR`, `DENY`, `QUARANTINE`), plus `/` for health checks.
- `zero_trust_rf_model.joblib`: Trained Random Forest pipeline (`StandardScaler` + `RandomForestClassifier`: 100 estimators, `max_depth=24`, `min_samples_leaf=2`, Accuracy: **97.22%**).
- `data set cleaning.ipynb`: Data preprocessing, feature selection (8 behavioral features), model evaluation, and comparison with Isolation Forest.
- `figures/`: High-resolution (300 DPI) evaluation plots (`fig_confusion_matrix.png`, `fig_roc_pr_curves.png`, `fig_feature_importance.png`).
- `requirements.txt`: Exact Python dependencies required to run the service.

---

## 🏗️ Edge Architecture & Progressive Policy Thresholds

- **Edge Deployment:** Hosted directly on the **Raspberry Pi 4 Edge Gateway** alongside the Policy Enforcement Point (PEP) for sub-2ms local inference (`http://127.0.0.1:8000/predict`).
- **Telemetry Window & Privacy:** All 8 behavioral features are aggregated by the Gateway over a **1.0-second tumbling window** per `device_id` using outer IP/TCP headers only (**Zero Payload Decryption** under mTLS).
- **4-Tier Progressive Decision (Aligned with Random Forest 50% Decision Boundary):**
  - **`ALLOW`** (`risk_score < 20%`): High-confidence benign traffic (`prediction = 0`); traffic flows normally.
  - **`MONITOR`** (`20% <= risk_score < 50%`): Minor anomaly or jitter below the 50% attack boundary (`prediction = 0`); triggers automated heightened logging without disrupting production.
  - **`DENY`** (`50% <= risk_score < 75%`): Moderate-confidence attack (`prediction = 1`); drops anomalous packets/session.
  - **`QUARANTINE`** (`risk_score >= 75%`): High-confidence attack (`prediction = 1`); enforces full `nftables` micro-segmentation isolation.
  - *(Note: The `.NET 8 Backend` PDP maintains the stateful `TrustScore` in the database using `risk_score` and enforces final policy transitions. The physical Relay Kill-Switch is the only optional manual override).*

---

## 🚀 Quick Start (Raspberry Pi 4 / Local Setup)

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the FastAPI server:**
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

3. **Interactive API Docs (Swagger UI):**
   Open `http://127.0.0.1:8000/docs` (or `http://<RASPBERRY_PI_IP>:8000/docs`) in your browser.

---

## 🔌 API Integration Contract (For .NET 8 Backend & Edge PEP)

### 1. Health Check: `GET /`
**Response:**
```json
{
  "status": "online",
  "model": "RandomForest-Edge-v1.2",
  "window_size_sec": 1.0,
  "policy_tiers": ["ALLOW", "MONITOR", "DENY", "QUARANTINE"]
}
```

### 2. Real-Time Inference: `POST /predict`

**Request Body (JSON — 1.0s Window per Device):**
```json
{
  "device_id": "ESP32_Sensor_01",
  "network_packets_all_count": 45.0,
  "network_packets_src_count": 25.0,
  "network_packets_dst_count": 20.0,
  "network_packet_size_avg": 68.4,
  "network_payload_length_avg": 24.0,
  "network_time_delta_avg": 0.015,
  "network_interval_packets": 0.012,
  "network_ips_dst_count": 1.0
}
```

**Response Body (JSON):**
```json
{
  "device_id": "ESP32_Sensor_01",
  "prediction": 0,
  "action": "ALLOW",
  "risk_score": 2.5,
  "inference_latency_ms": 1.35
}
```
- **`device_id`**: Unique identifier of the monitored IoT device.
- **`prediction`**: `0` = Benign traffic, `1` = Attack / Anomaly.
- **`action`**: Progressive policy tier (`ALLOW`, `MONITOR`, `DENY`, or `QUARANTINE`) matching the ERD and Class Diagram enums.
- **`risk_score`**: Continuous attack probability percentage (`0.0` to `100.0`) used by the `.NET 8 Backend` to update the device's cumulative `TrustScore`.
- **`inference_latency_ms`**: Model decision time in milliseconds.
