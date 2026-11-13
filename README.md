# Enterprise CyberGuard X
> **AI-Powered Enterprise Cybersecurity Threat Detection, Investigation and Monitoring Platform**

---

## 1. Project Overview & Research Architecture
**Enterprise CyberGuard X** is an end-to-end Security Operations Center (SOC) platform engineered to overcome the closed-set classification limitation in enterprise cyber defense.

```
                    Enterprise Security Logs (Auth, Endpoint, Network)
                                          │
                                          ▼
                               [Data Ingestion Module]
                            (CSV / JSON / Stream Parser)
                                          │
                                          ▼
                         [Log Parsing & Normalization]
                                          │
                                          ▼
                              [Feature Extraction]
                                          │
             ┌────────────────────────────┼────────────────────────────┐
             ▼                            ▼                            ▼
      [User / Identity]          [Endpoint / Device]           [Network Traffic]
       Login frequency,            Process execution,          Port scanning,
       Off-hours access,           LOLBAS obfuscation,         Lateral SMB,
       Impossible travel           Denoising Autoencoder       Flow volumes, GAT
             │                            │                            │
             └────────────────────────────┼────────────────────────────┘
                                          ▼
                              [Hybrid Detection Engine]
                   ┌──────────────────────┴──────────────────────┐
                   ▼                                             ▼
          [Known Threat Detection]                      [Open-Set Recognition]
         (XGBoost / LightGBM Multi-Class)              (Mahalanobis Latent Space
                                                        & Autoencoder Residual)
                   └──────────────────────┬──────────────────────┘
                                          ▼
                             [Cross-Layer Correlation]
                        (Multi-Stage Kill Chain Tracking)
                                          │
                                          ▼
                                [Explainable AI Layer]
                         (TreeSHAP Feature Attributions
                          & Evidence-Gated MITRE ATT&CK)
                                          │
                                          ▼
                            [Agentic RAG Investigation]
                         (FAISS Vector Search over ATT&CK
                          & Zero-Hallucination Guardrails)
                                          │
                                          ▼
                         [Interactive Modern SOC Dashboard]
                         (React 18 + Vite + Tailwind + WS)
```

---

## 2. Key Capabilities & Empirical Results

### Open-Set Decision Logic
Every incoming event is evaluated through a hybrid multi-layer gate:
$$\text{Verdict} = \begin{cases} 
\text{BENIGN} & \text{if anomaly score is low and predicted benign} \\
\text{KNOWN THREAT} & \text{if classified into known attack class with confidence } \ge 0.70 \\
\text{UNKNOWN / NOVEL THREAT} & \text{if anomalous and Mahalanobis distance } d_M > 4.20 \text{ or reconstruction error } > 0.12 \\
\text{SUSPICIOUS} & \text{otherwise}
\end{cases}$$

### Empirical Evaluation Metrics (Tested on Benchmark Test Split)
- **Supervised Classifier (XGBoost)**: 100% accuracy on known threat classes (`Brute Force`, `Port Scan`, `LOLBAS Execution`, `Lateral Movement`, `Benign`).
- **Unsupervised Anomaly (Isolation Forest)**: Precision `0.953`, Recall `0.988`, F1-Score `0.970`.
- **Open-Set Novel Threat Detection (150 Held-Out Zero-Day Attacks)**:
  - Average known-class latent distance: **`1.04`**
  - Average novel threat latent distance: **`258.02`**
  - Novel Threat Rejection / Detection Rate: **`100%`**

---

## 3. Technology Stack
- **Frontend**: React 18, Vite, Tailwind CSS, Recharts, Lucide React, WebSockets.
- **Backend**: Python 3.10+, FastAPI, Uvicorn, SQLAlchemy, Pydantic v2, WebSockets.
- **Machine Learning**: Scikit-learn, XGBoost, PyTorch, PyTorch Geometric, NetworkX, SHAP.
- **RAG & Vector Search**: FAISS vector search, local TF-IDF / Sentence Transformers, MITRE ATT&CK knowledge base.
- **Database**: SQLite (default local dev) / PostgreSQL 16 (production).

---

## 4. How to Run Locally (Windows / VS Code)

### Prerequisites
- Python 3.10+ (tested on Python 3.13)
- Node.js 18+ and npm

### Terminal 1: Backend Setup
```powershell
# 1. Install backend requirements
cd backend
python -m pip install -r requirements.txt

# 2. Start the FastAPI server (auto-creates tables and seeds baseline)
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Docs (Swagger): [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- API Health Check: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)
- WebSocket Stream: `ws://127.0.0.1:8000/ws/live-events`

### Terminal 2: Frontend Setup
```powershell
# 1. Install frontend packages and start Vite dev server
cd frontend
npm install
npm run dev
```
- SOC Dashboard: **[http://localhost:5173](http://localhost:5173)**
- Built-in Vite proxy automatically maps `/api` and `/ws` to `http://127.0.0.1:8000`.

### Run Test Suite
```powershell
python -m pytest backend/tests/test_endpoints_e2e.py -v
```

---

## 5. Docker Deployment
```powershell
docker-compose up --build
```
- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8000`
- PostgreSQL: `localhost:5432`

