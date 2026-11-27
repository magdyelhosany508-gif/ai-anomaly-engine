import os
import time
import joblib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

# تهيئة تطبيق FastAPI الخاص بمحرك الذكاء الاصطناعي
app = FastAPI(
    title="Zero-Trust Bio-IoT Sentinel - AI Inference Engine",
    description=(
        "Real-time behavioral anomaly detection microservice using Random Forest"
    ),
    version="1.2.1",
)

# تحميل الموديل المدرب (Pipeline: StandardScaler + RandomForest) مرة واحدة عند التشغيل
MODEL_PATH = os.path.join(
    os.path.dirname(__file__), "zero_trust_rf_model.joblib"
)
ai_pipeline = joblib.load(MODEL_PATH)

# استخراج معاملات الـ StandardScaler لتطبيقها مباشرة بـ NumPy (أسرع وبدون تحذيرات متكررة)
scaler = ai_pipeline[0]
scaler_mean = scaler.mean_.astype(np.float32)
scaler_scale = scaler.scale_.astype(np.float32)

rf_model = ai_pipeline.named_steps["rf"]
rf_model.n_jobs = 1

# تسخين الموديل في الذاكرة (Warm-up) لضمان أقصى سرعة لأول طلب فعلي
_dummy_input = np.zeros((1, 8), dtype=np.float32)
rf_model.predict_proba(_dummy_input)


# تعريف شكل البيانات (JSON) التي سيرسلها الـ Gateway (نافذة زمنية = 1.0 ثانية)
class TrafficWindow(BaseModel):
  model_config = ConfigDict(populate_by_name=True)

  device_id: str
  network_packets_all_count: float
  network_packets_src_count: float
  network_packets_dst_count: float
  network_packet_size_avg: float = Field(alias="network_packet-size_avg")
  network_payload_length_avg: float = Field(alias="network_payload-length_avg")
  network_time_delta_avg: float = Field(alias="network_time-delta_avg")
  network_interval_packets: float = Field(alias="network_interval-packets")
  network_ips_dst_count: float


def map_progressive_policy(risk_score: float) -> str:
  """
    تحويل نسبة الخطورة اللحظية إلى أحد مستويات القرار الأربعة المعتمدة في الـ ERD والـ Class Diagram:
    ALLOW -> MONITOR -> DENY -> QUARANTINE
    تتطابق عتبة 50% مع الحد الفاصل الافتراضي لتصنيف Random Forest (0 = Benign, 1 = Attack).
    """
  if risk_score < 20.0:
    return "ALLOW"
  elif risk_score < 50.0:
    return "MONITOR"
  elif risk_score < 75.0:
    return "DENY"
  else:
    return "QUARANTINE"


# نقطة فحص للتأكد من أن السيرفر يعمل
@app.get("/")
def health_check():
  return {
      "status": "online",
      "model": "RandomForest-Edge-v1.2.1",
      "window_size_sec": 1.0,
      "policy_tiers": ["ALLOW", "MONITOR", "DENY", "QUARANTINE"],
  }


# نقطة التنبؤ واستخراج نسبة الخطورة والقرار المتدرج
@app.post("/predict")
def predict_traffic(data: TrafficWindow):
  start_time = time.perf_counter()

  # ترتيب الـ 8 خصائص بنفس الترتيب الدقيق المستخدم أثناء التدريب
  features = np.array(
      [[
          data.network_packets_all_count,
          data.network_packets_src_count,
          data.network_packets_dst_count,
          data.network_packet_size_avg,
          data.network_payload_length_avg,
          data.network_time_delta_avg,
          data.network_interval_packets,
          data.network_ips_dst_count,
      ]],
      dtype=np.float32,
  )

  # تطبيق الـ StandardScaler وحساب احتمالية الهجوم مرة واحدة فقط
  features_scaled = (features - scaler_mean) / scaler_scale
  attack_probability = float(rf_model.predict_proba(features_scaled)[0][1])

  prediction = 1 if attack_probability >= 0.5 else 0
  risk_score = round(attack_probability * 100, 2)
  action = map_progressive_policy(risk_score)

  # حساب زمن اتخاذ القرار بالمللي ثانية (ms)
  latency_ms = (time.perf_counter() - start_time) * 1_000

  return {
      "device_id": data.device_id,
      "prediction": prediction,
      "action": action,
      "risk_score": risk_score,
      "inference_latency_ms": round(latency_ms, 3),
  }


if __name__ == "__main__":
  import uvicorn

  print("\n==========================================")
  print("Local Test URL:   http://127.0.0.1:8000")
  print("Interactive Docs: http://127.0.0.1:8000/docs")
  print("==========================================\n")
  uvicorn.run(app, host="0.0.0.0", port=8000)
