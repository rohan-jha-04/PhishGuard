# PhishGuard 🛡️
### Explainable Machine Learning-Based Phishing URL Detection System
**Academic CSE Semester Capstone Project (2026)**  
*Developed with Python (FastAPI), React (Vite & Tailwind CSS), Scikit-Learn, and SQLite.*

---

## 📌 Abstract & Objective

Phishing attacks use deceptive URLs to trick users into revealing sensitive information, including login credentials and financial details. Traditional blacklist-based detection methods may fail to identify newly created or previously unseen malicious URLs.

**PhishGuard** is a zero-page-execution phishing URL detection platform that combines machine learning, lexical URL analysis, and real-time domain verification to classify submitted URLs into three categories: **Safe, Suspicious, and Phishing** without fetching or rendering untrusted webpage HTML or JavaScript.

The system extracts 20 lexical and structural URL features (with browser-standard scheme normalization and global authority domain protection) and uses machine learning classifiers, including Random Forest and Logistic Regression, alongside live checks for brand typosquatting/homoglyphs, DNS resolution (`NXDOMAIN`), RDAP domain age, and TLS certificates. Its explainability layer combines mathematically derived **Tree-Path feature attribution** with real-time verification cards behind each prediction.

PhishGuard includes JWT user authentication, scan history, statistical dashboards, rate-limited endpoints, and an administrative model-governance portal.

The current benchmark uses a project-generated synthetic dataset. Its evaluation results demonstrate performance on that dataset and do not establish real-world detection accuracy.

---

## 🎨 Design Philosophy & Color Palette
PhishGuard is styled as a premium cybersecurity dashboard adhering strictly to a focused three-color palette:
- 🌌 **Deep Navy (`#101827`):** Primary canvas, deep surfaces, dark elevations.
- ⚡ **Electric Green (`#27D17F`):** Brand accent, verified safe status, cyber highlights.
- ❄️ **Crisp Offwhite (`#F8FAFC`):** High-contrast typography and clean reading surfaces.
- Semantic accents (`#EF4444` Crimson / `#F59E0B` Amber) are strictly reserved for threat severity indicators.

---

## 🚀 Key Modules
1. **Landing Page:** Interactive quick-scan bar, 4-stage pipeline explanation, and empirical benchmark highlights.
2. **URL Scanner:** Zero-execution heuristic + real-time parser with scheme/XSS validation, animated radar scanner, risk gauge dial ($0-100$), and defanged URL representation (`hxxps[://]...`).
3. **Explainable AI (XAI) & Real-Time Verification Engine:** Analyzes 20 lexical and structural URL features using exact **Tree-Path feature attribution** (Random Forest decision-path contributions) paired with parallel, zero-page-execution live checks:
   - **Brand Typosquatting & Homoglyph Detection:** Catches Punycode (`xn--`), visual lookalikes (`I` vs `l`, `0` vs `o`, `rn` vs `m`), and Levenshtein edit-distance impersonation.
   - **Live DNS Resolution:** Distinguishes active `A`/`AAAA` hosts from unresolvable / `NXDOMAIN` domains.
   - **Live RDAP Registry & Domain Age:** Queries public RDAP registries (`rdap.org`) for registration status and domain age (flagging newly registered domains `< 30` days old and unregistered `NXDOMAIN` + HTTP `404` hosts).
   - **Live TLS/SSL Handshake:** Validates certificate trust, hostname match, issuer, and age on port `443`.
4. **User Threat Dashboard:** Daily scanning frequency charts, categorical threat distribution donut chart, and frequent threat indicator bar charts rendered via Recharts.
5. **Scan History:** Permanent SQLite audit log with pagination, search, status filtering, and JSON export.
6. **Admin & Model Governance Portal:** Side-by-side comparison of **Random Forest** vs. **Logistic Regression**, interactive confusion matrix heatmaps, feature importance rankings, and one-click model pipeline retraining.
7. **Embedded Academic Portal:** Full SRS, architecture diagrams, mathematical formulations, and ER designs viewable in-browser.

---

## 📊 Empirical ML Benchmarks (Synthetic Holdout Test Split N=361)

PhishGuard was evaluated using a rebalanced project-generated synthetic URL benchmark containing 1,801 samples. The dataset consists of manually defined benign and phishing-like URL patterns (including HTTP benign sites and HTTPS phishing templates to avoid protocol bias) expanded through predefined templates.

**Dataset composition:**
- Total samples: 1,801
- Benign samples: 877
- Phishing samples: 924
- Training samples: 1,440 (80%)
- Testing samples: 361 (20%)

**Model evaluation results:**

| Metric | Random Forest | Logistic Regression |
|---|---:|---:|
| Accuracy | 100.00% | 100.00% |
| Precision | 100.00% | 100.00% |
| Recall | 100.00% | 100.00% |
| F1-Score | 100.00% | 100.00% |
| ROC-AUC | 1.0000 | 1.0000 |

**Confusion Matrices:**

- Random Forest: `[[176, 0], [0, 185]]`
- Logistic Regression: `[[176, 0], [0, 185]]`

**Important Academic Limitation:**

These results represent performance on the project's synthetic holdout dataset only. Because the dataset is generated using predefined URL patterns and templates, the reported metrics should not be interpreted as evidence of equivalent performance on real-world phishing URLs. Independent evaluation using verified external datasets is required to establish real-world generalization.

---

## 🛠️ Tech Stack
- **Frontend:** React 18, Vite, Tailwind CSS, Recharts, Lucide React Icons, Axios.
- **Backend:** Python 3.10+, FastAPI, Uvicorn, Pydantic v2, httpx, SlowAPI.
- **Machine Learning & Verification:** Scikit-Learn, Pandas, NumPy, Joblib, live DNS (`socket`), TLS (`ssl`), and RDAP lookups.
- **Database:** SQLite 3, SQLAlchemy 2.0 ORM.
- **Security:** Bcrypt salted hashing, JWT Bearer tokens, CORS allowlisting, rate limiting, and zero-execution defanged string parsers.

---

## ⚡ Quick Start on Windows

### Option 1: Master Single-Click Launcher
Simply double-click:
```cmd
start_all.bat
```
*This launches both the FastAPI backend (port 8000) and the React Vite frontend (port 5173), then automatically opens your browser to http://localhost:5173.*

### Option 2: Individual Launch Scripts
1. **Backend:** Double-click `start_backend.bat` (Runs on `http://127.0.0.1:8000`, API Docs at `http://127.0.0.1:8000/docs`).
2. **Frontend:** Double-click `start_frontend.bat` (Runs on `http://localhost:5173`).

### Option 3: Manual Command Line Startup
**Terminal 1 (Backend):**
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
# Edit backend/.env and set a 32+ character SECRET_KEY and account passwords
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2 (Frontend):**
```bash
cd frontend
npm install
npm run dev
```

---

## 🎓 Faculty Evaluation & Demo Accounts

PhishGuard supports role-based accounts (**Admin** and **Student Researcher**) configured via environment variables in `backend/.env`.

**Available roles:**

- **Lead Security Auditor (Admin):** Accesses system-wide analytics, researcher management, model evaluation, dataset provenance, and asynchronous model retraining.
- **Student Researcher:** Accesses URL scanning, personal scan history, and user-level threat analytics.

**Login Instructions:**

Set `DEFAULT_ADMIN_PASSWORD` and `DEFAULT_USER_PASSWORD` in `backend/.env` before starting the backend, or register a new user account on the Register page. Instant one-click demo login is disabled by default (`ENABLE_DEMO_LOGIN=false`) for security.

**Security Note:** Never commit `backend/.env` or `phishguard.db` to public repositories. Copy [`backend/.env.example`](backend/.env.example) to configure a fresh environment.

### Quick-Test URL Samples Built into Scanner

The following URLs are illustrative test inputs for demonstrating different URL structures and detection indicators. Their classifications are produced by the PhishGuard model and should not be treated as independently verified threat intelligence.

1. `https://en.wikipedia.org/wiki/Phishing` — Standard HTTPS URL.
2. `http://192.168.1.100/paypal/login.php?cmd=update` — Direct IP address with a suspicious login path.
3. `https://appleid.apple.com.secure-update-notice.top/account` — Brand-name impersonation through a nested subdomain.
4. `http://bit.ly/34xPaypalSecurityAlert` — URL shortener example.
5. `http://google.com@phish-credentials-steal.net/auth/verify` — URL containing an `@` symbol and a deceptive hostname pattern.

---

## 📂 Repository Structure
- `backend/` — FastAPI API, SQLAlchemy models, ML training/inference pipeline, real-time DNS/RDAP/TLS verifier, and Pytest suite
- `frontend/` — React + Vite dashboard, URL scanner UI, XAI explanation cards, and Admin portal
- `start_all.bat`, `start_backend.bat`, `start_frontend.bat` — Windows quick-launch scripts

