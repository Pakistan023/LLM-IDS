# Architecture

## Data flow

```
                 ┌───────────────────────┐
                 │   Traffic Source       │
                 │  (Simulator or Scapy)  │
                 └───────────┬────────────┘
                             │  raw packets / synthetic events
                             ▼
                 ┌───────────────────────┐
                 │  Feature Extractor     │  -> FlowRecord windows
                 │  (aggregation, stats)  │  -> numeric matrix + LLM text summary
                 └───────────┬────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                     ▼
┌───────────────┐   ┌────────────────┐   ┌────────────────────┐
│ Signature      │   │ ML Classifier  │   │ LLM Analyzer        │
│ Engine         │   │ (RandomForest) │   │ (Claude / GPT-4)     │
│ (rules.yaml)   │   │                │   │  + RAG knowledge base│
└───────┬────────┘   └───────┬────────┘   └──────────┬──────────┘
        │                    │                        │
        └────────────────────┼────────────────────────┘
                             ▼
                 ┌───────────────────────┐
                 │    Alert Manager       │  normalizes + persists
                 └───────────┬────────────┘
                             ▼
                 ┌───────────────────────┐
                 │   SQLite Alert Store   │
                 └───────────┬────────────┘
                             ▼
      ┌───────────────┬─────────────────┬────────────────────┐
      ▼               ▼                 ▼                    ▼
 Streamlit UI   NLP Digest Summarizer   Voice Assistant   Accuracy Benchmark
 (dashboard)    (shift handoff report)  (chat / speech)   (compare_accuracy.py)
```

## Why three detectors?

| Detector             | Strengths                                   | Weaknesses                                  |
|-----------------------|----------------------------------------------|----------------------------------------------|
| Signature Engine      | Deterministic, fast, fully explainable       | Only catches known patterns, brittle to variants |
| ML Classifier         | Learns statistical patterns, generalizes somewhat | Not interpretable, needs labeled training data |
| LLM Analyzer          | Explains *why*, reasons over context, grounded via RAG | Latency/cost of API calls, needs validation, non-deterministic |

The assignment specifically asks to benchmark the LLM approach against a
traditional signature-based IDS. `src/evaluation/compare_accuracy.py`
runs all three detectors against the identical labeled synthetic dataset
and reports accuracy/precision/recall/F1 side by side, which the
dashboard's "Accuracy Benchmark" tab also visualizes.

## RAG design

To keep the bonus RAG feature dependency-free and offline-capable, the
knowledge base (`src/rag/knowledge_base.py`) uses TF-IDF + cosine
similarity over a small curated set of threat-intelligence markdown
documents (`src/rag/threat_docs/`), rather than requiring a vector
database. The retrieved context is injected into the LLM prompt as
grounding material, so the model's explanations reference established
threat patterns and MITRE ATT&CK mappings instead of purely improvising.

This is a drop-in-replaceable component: swapping `TfidfVectorizer` for a
sentence-transformer embedding model plus FAISS/Chroma requires no changes
to the calling code, since the public interface is just
`retrieve(query, top_k) -> List[RetrievedDoc]`.

## Extensibility notes

- **New attack signatures:** add entries to `config/signatures.yaml` — no
  code changes required, since conditions are evaluated against the
  `FlowRecord` field dict.
- **New threat-intel docs:** drop a `.md` file into
  `src/rag/threat_docs/` — it's picked up automatically on next start.
- **Swapping LLM providers:** set `LLM_PROVIDER=openai` or `anthropic` in
  `.env`; both are implemented behind the same `LLMAnalyzer` interface.
- **Real packet capture:** implement/extend `src/capture/packet_capture.py`
  (Scapy is already wired up); the rest of the pipeline is capture-source
  agnostic because everything downstream operates on `FlowRecord` objects.
