# 🛡️ AI-Powered Phishing Detection

🚀 Built by Team Adhiyant  
🎉 Selected for the **HackIITK Finals 2025**

An AI-powered system that detects phishing **emails** & **URLs** using NLP and ML, with an interactive Streamlit dashboard.
- **BERT-based NLP model** (for email text classification)
- **RandomForest-based URL classifier** (with handcrafted lexical features)
- **Threat Intelligence Simulator** (with mock or API-driven feeds)
- Interactive **visual dashboards** with Plotly

---

## 🚀 Features
- Detects phishing attempts in emails & URLs
- Extracts and analyzes URLs embedded in emails
- Generates threat intelligence summaries
- Interactive Streamlit dashboard with real-time analysis
- Report generation with charts and recommendations

---

## 📂 Project Structure
- app.py # Main Streamlit app
- components/ # UI elements & dashboard components
- models/ # ML models (BERT + URL Classifier)
- utils/ # Data processing & threat intel logic
- requirements.txt # Dependencies
- scripts/ # Helper scripts for testing/training

---

### 1️⃣ Clone the repository
```bash
git clone https://github.com/your-username/phishing-detector.git
cd phishing-detector
