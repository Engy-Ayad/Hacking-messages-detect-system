# Hacking-messages-detect-system

Here is a professional, high-impact `README.md` layout tailored for your GitHub repository. It clearly presents your multi-layered security architecture, highlights the shift from brittle manual rule-matching to an API-driven threat intelligence pipeline, and demonstrates a production-grade approach to the panel.

---

# Deraa (درع): AI-Driven Phishing Detection System for Egyptian Dialect SMS

Deraa (Arabic for Shield) is a production-grade, multi-layered security backend designed to detect and classify SMS phishing (smishing) attempts. While traditional security filters rely on static keyword matching, Deraa combines natural language processing (NLP) tailored to the nuances of the Egyptian dialect with live global threat intelligence to identify evolving social engineering vectors, including banking fraud, fake package deliveries, and fraudulent cash rewards.

---

## Core Architecture

Deraa employs a modular, three-layer pipeline to analyze incoming text messages and extracted screenshot text, ensuring high accuracy and minimal false positives.

### Layer 1: NLP Intent & Context Classifier

Processes the message text using a TF-IDF vectorization matrix paired with a Logistic Regression classifier trained on Egyptian dialect phishing patterns. It maps semantic urgency, fear tactics, or fraudulent promises rather than relying on exact word matches.

### Layer 2: Entity & Sender Verification Engine

Cross-checks the sender's identity against an authoritative directory of trusted institutions (e.g., Egyptian banks, telecom operators, national utilities). It flags discrepancies, such as a message claiming to be from a financial institution but arriving from a standard 11-digit mobile number.

### Layer 3: Live Threat Intelligence Pipeline

Extracts embedded URLs and submits them directly to the VirusTotal API. By converting URLs into deterministic base64 identifiers, the system queries a live global network of over 70 security engines. If a domain is unindexed or freshly registered, the pipeline automatically submits it for sandboxing, eliminating the need to maintain a manual database of suspicious top-level domains (TLDs) like `.cc` or `.xyz`.

---

## Key Features

* **Dialect-Aware Processing:** Specialized text normalization tailored to Arabic script variations and colloquial Egyptian phrasing.
* **API-Driven Threat Intelligence:** Live verification of suspicious links via global security databases, capturing zero-day phishing sites immediately.
* **Integrated OCR Pipeline:** Powered by EasyOCR to extract Arabic and English text directly from uploaded screenshots or images of SMS logs.
* **Deterministic Risk Scoring:** Aggregates multi-layer analytical data into a calibrated sigmoid risk curve, providing clear severity levels ranging from `SAFE` to `CRITICAL`.
* **Actionable Recommendations:** Generates contextual mitigation steps for end-users based on the specific architectural flags triggered during analysis.

---

## Technical Stack

* **Backend Framework:** FastAPI (Asynchronous Python Web Framework)
* **Machine Learning & NLP:** Scikit-Learn (TF-IDF Vectorizer, Logistic Regression)
* **Optical Character Recognition (OCR):** EasyOCR, PyTorch
* **Threat Intelligence Integration:** VirusTotal API v3
* **Data Validation:** Pydantic v2
* **Server Gateway:** Uvicorn

---

## API Endpoints

### 1. Text Analysis

* **Endpoint:** `POST /analyze-text`
* **Payload:**
```json
{
  "text": "المندوب سوف يعيد شحنه يرجى تأكيد عنوان التوصيل ocmrazx.cc",
  "sender": "+201280161130"
}

```



### 2. Image/Screenshot Analysis

* **Endpoint:** `POST /analyze-image`
* **Payload:** Multipart Form Data (`file`: Image, `sender`: Optional String)

---

## Installation & Setup

### Prerequisites

* Python 3.10 or higher
* A valid VirusTotal API Key

### Deployment Steps

1. Clone the repository:
```bash
git clone https://github.com/yourusername/deraa-backend.git
cd deraa-backend

```


2. Create and activate a isolated virtual environment:
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\Activate.ps1
# On macOS/Linux:
source venv/bin/activate

```


3. Install the required dependencies:
```bash
pip install -r requirements.txt

```


4. Configure your environment variable in `main.py`:
```python
VIRUSTOTAL_API_KEY = "your_actual_api_key_here"

```


5. Launch the local development server:
```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload

```
