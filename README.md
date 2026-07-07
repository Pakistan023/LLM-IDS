# 🛡️ LLM-IDS — AI-Powered Intrusion Detection System

An intrusion detection system that uses a large language model (Claude or
GPT-4) to classify network traffic anomalies **and explain them in plain
English**, benchmarked against a traditional signature-based IDS
(Suricata/Snort-style rules) and a scikit-learn ML classifier.

Built for **Category A — AI & LLM-Powered Security Systems**.

---

## ✨ Features

- **Three-detector pipeline**: signature engine, ML classifier (RandomForest), and LLM analyzer (Claude/GPT-4) all run on the same traffic, side by side.
- **Natural-language threat reports**: the LLM explains *why* a flow is suspicious, cites likely MITRE ATT&CK techniques, and recommends a next action — not just a label.
- **RAG-grounded reasoning (bonus)**: a lightweight, dependency-free threat-intelligence knowledge base is retrieved and injected into every LLM prompt.
- **Real-time alert NLP summarizer (bonus)**: turns dozens of raw alerts into a concise SOC shift-handoff digest.
- **Voice-driven security assistant (bonus)**: ask "summarize critical alerts" out loud or by text.
- **Accuracy benchmark harness**: quantitatively compares signature vs. ML vs. LLM detection on identical labeled traffic (precision/recall/F1/accuracy).
- **Professional Streamlit dashboard**: live overview, detector comparison, full LLM reports, filterable alert log, digest, chat assistant, and benchmark charts.
- **Works with zero external dependencies for demo purposes** via a built-in synthetic traffic simulator — no root privileges, NIC, or pcap library required to try it out. Swap in real packet capture (Scapy/PyShark) when ready.

---

## 🗂️ Project structure

```
llm-ids/
├── main.py                       # Headless CLI runner
├── requirements.txt
├── .env.example                  # Copy to .env and add your API key(s)
├── config/
│   ├── config.yaml                # Central configuration
│   └── signatures.yaml            # Suricata/Snort-style detection rules
├── src/
│   ├── capture/
│   │   ├── traffic_simulator.py   # Synthetic traffic + injected attacks
│   │   └── packet_capture.py      # Live capture via Scapy (optional)
│   ├── features/
│   │   └── feature_extractor.py   # FlowRecord -> ML matrix / LLM text
│   ├── detection/
│   │   ├── signature_engine.py    # Rule-based baseline detector
│   │   ├── ml_classifier.py       # RandomForest anomaly classifier
│   │   └── llm_analyzer.py        # Claude/GPT-4 classification + explanation
│   ├── rag/
│   │   ├── knowledge_base.py      # TF-IDF retrieval over threat docs
│   │   └── threat_docs/*.md       # Curated threat-intel reference docs
│   ├── alerts/
│   │   ├── alert_manager.py       # Orchestrates all 3 detectors
│   │   └── nlp_summarizer.py      # Shift-digest generator (bonus)
│   ├── voice/
│   │   └── voice_assistant.py     # Voice/text security assistant (bonus)
│   ├── evaluation/
│   │   └── compare_accuracy.py    # Signature vs ML vs LLM benchmark
│   ├── db/
│   │   └── database.py            # SQLite alert storage
│   └── utils/
│       ├── logger.py
│       └── config_loader.py
├── dashboard/
│   └── app.py                     # Streamlit UI
├── tests/                         # Unit tests
└── docs/
    └── ARCHITECTURE.md
```

---

## 🚀 Quick start

### 1. Install dependencies

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

> Scapy/PyShark require libpcap (Linux/macOS) or Npcap (Windows) for
> **live** capture. They are **not required** to run the demo — the
> synthetic traffic simulator is the default data source.

### 2. Configure your LLM API key

```bash
cp .env.example .env
```

Edit `.env` and set **one** of:

```
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

or

```
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
```

### 3. Launch the dashboard

```bash
streamlit run dashboard/app.py
```

Open the URL Streamlit prints (usually `http://localhost:8501`), then in
the sidebar click **▶ Analyze one window** to generate synthetic traffic
and see all three detectors fire, including the LLM's natural-language
threat report.

### 4. (Optional) Run headless

```bash
python main.py --mode simulate --interval 5 --batch-size 30
```

Skip the LLM entirely (no API key needed) for signature+ML-only testing:

```bash
python main.py --no-llm
```

### 5. Run the accuracy benchmark

```bash
python -m src.evaluation.compare_accuracy --n-flows 300 --no-llm   # fast, no API cost
python -m src.evaluation.compare_accuracy --n-flows 300            # includes LLM (uses API calls)
```

### 6. Run tests

```bash
python -m pytest tests/ -v
```

---

## 🔍 How the comparison works

`src/evaluation/compare_accuracy.py` generates one labeled synthetic
traffic set and runs it through all three detectors, reporting accuracy,
precision, recall, and F1 for each — giving an apples-to-apples answer to
"how does the LLM approach compare to signature-based IDS?" as required
by the assignment. See `docs/ARCHITECTURE.md` for the full design
rationale and a breakdown of each detector's strengths/weaknesses.

---

## ⚠️ Notes on live packet capture

Live capture (`src/capture/packet_capture.py`) uses Scapy and requires:
- Root/Administrator privileges
- libpcap (Linux/macOS) or Npcap (Windows) installed
- A network interface name (find yours with `ip a` / `ifconfig` / `ipconfig`)

Run with `python main.py --mode live --interface eth0` (adjust interface
name). For any environment without these prerequisites — including most
sandboxes, CI runners, and cloud shells — use the default simulator.

---

## 🧩 Tech stack

Python · Scapy/PyShark · Anthropic API · OpenAI API · scikit-learn ·
Streamlit · Plotly · SQLAlchemy/SQLite · SpeechRecognition/pyttsx3
