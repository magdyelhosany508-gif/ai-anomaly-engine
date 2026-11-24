import os
import time
import joblib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel

# تهيئة تطبيق FastAPI الخاص بمحرك الذكاء الاصطناعي
app = FastAPI(
    title="Zero-Trust Bio-IoT Sentinel - AI Inference Engine",
    description=(
        "Real-time behavioral anomaly detection microservice using Random Forest"
    ),
    version="1.0.0",
)

# تحميل الموديل المدرب مرة واحدة عند تشغيل السيرفر
MODEL_PATH = os.path.join(
    os.path.dirname(__file__), "zero_trust_rf_model.joblib"
)
ai_pipeline = joblib.load(MODEL_PATH)

# ضبط عدد الأنوية على 1 لتجنب تأخير فتح الـ Threads عند فحص عينة واحدة في الوقت الفعلي
ai_pipeline.named_steps["rf"].n_jobs = 1

# تسخين الموديل في الذاكرة (Warm-up) لضمان أقصى سرعة لأول طلب فعلي
_dummy_input = np.zeros((1, 8), dtype=np.float32)
ai_pipeline.predict(_dummy_input)


# تعريف شكل البيانات (JSON) التي سيرسلها الـ Gateway أو الـ .NET Backend
class TrafficWindow(BaseModel):
  device_id: str
  network_packets_all_count: float
  network_packets_src_count: float
  network_packets_dst_count: float
  network_packet_size_avg: float
  network_payload_length_avg: float
  network_time_delta_avg: float
  network_interval_packets: float
  network_ips_dst_count: float


# نقطة فحص للتأكد من أن السيرفر يعمل
@app.get("/")
def health_check():
  return {"status": "online", "model": "RandomForest-Edge-v1"}


# نقطة التنبؤ واتخاذ قرار السماح أو العزل الفوري
@app.post("/predict")
def predict_traffic(data: TrafficWindow):
  start_time = time.perf_counter()

  # تحويل المدخلات مباشرة إلى مصفوفة NumPy سريعة بدون حمل إضافي على الذاكرة
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

  # استخراج القرار (0 = طبيعي، 1 = هجوم) واحتمالية الخطورة
  prediction = int(ai_pipeline.predict(features)[0])
  attack_probability = float(ai_pipeline.predict_proba(features)[0][1])

  # حساب زمن اتخاذ القرار بالمايكروثانية
  latency_us = (time.perf_counter() - start_time) * 1_000_000
  action = "ISOLATE" if prediction == 1 else "ALLOW"

  return {
      "device_id": data.device_id,
      "prediction": prediction,
      "action": action,
      "risk_score": round(attack_probability * 100, 2),
      "inference_latency_us": round(latency_us, 2),
  }


# تشغيل السيرفر مباشرة عند تنفيذ الملف
if __name__ == "__main__":
  import uvicorn

  uvicorn.run(app, host="127.0.0.1", port=8000)