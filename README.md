# 🛡️ Zero-Trust Bio-IoT Sentinel — AI Behavioral Anomaly Engine

Real-time behavioral anomaly detection microservice for Industrial IoT (IIoT) networks using a tuned **Random Forest Classifier** trained on the **CIC IIoT 2025** dataset.

## 📁 Repository Structure
- `main.py`: FastAPI inference microservice exposing `/predict` for real-time traffic classification (`ALLOW` vs `ISOLATE`) and `/` for health checks.
- `zero_trust_rf_model.joblib`: Trained Random Forest pipeline (100 estimators, `max_depth=24`, `min_samples_leaf=2`, Accuracy: **97.22%**).
- `data set cleaning.ipynb`: Data preprocessing, feature selection (8 behavioral features), model evaluation, and comparison with Isolation Forest.
- `figures/`: High-resolution (300 DPI) evaluation plots (`fig_confusion_matrix.png`, `fig_roc_pr_curves.png`, `fig_feature_importance.png`).
- `requirements.txt`: Exact Python dependencies required to run the service.

---

## 🚀 Quick Start (Local / Edge Setup)

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the FastAPI server:**
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. **Interactive API Docs (Swagger UI):**
   Open `http://127.0.0.1:8000/docs` in your browser.

---

## 🔌 API Integration Contract (For .NET Backend & Edge PEP)

### 1. Health Check: `GET /`
**Response:**
```json
{
  "status": "online",
  "model": "RandomForest-Edge-v1"
}
```

### 2. Real-Time Inference: `POST /predict`

**Request Body (JSON):**
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
  "inference_latency_us": 1350.4
}
```
- **`prediction`**: `0` = Normal traffic, `1` = Attack / Anomaly.
- **`action`**: `ALLOW` (benign traffic) or `ISOLATE` (triggers immediate micro-segmentation via `nftables`).
- **`risk_score`**: Attack probability percentage (`0.0` to `100.0`).
- **`inference_latency_us`**: Model decision time in microseconds.