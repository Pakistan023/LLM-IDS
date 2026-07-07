"""
LLM-powered traffic analyzer.

Feeds compact, structured flow summaries to Claude (Anthropic) or GPT-4
(OpenAI) and asks for a strict-JSON classification + a human-readable
explanation of *why* the flow looks the way it does. The RAG knowledge
base is queried first and its content is injected into the prompt as
grounding context, so explanations cite real threat-intel patterns rather
than the model's unaided guesswork.

This is the centerpiece differentiator vs. the signature engine (rigid,
no explanation) and the ML classifier (accurate but not interpretable):
the LLM produces an analyst-readable narrative report per flow/window.
"""

import json
import os
from dataclasses import dataclass, field
from typing import List, Optional

from src.capture.traffic_simulator import FlowRecord
from src.features.feature_extractor import batch_to_llm_summary, flow_to_llm_summary
from src.rag.knowledge_base import ThreatKnowledgeBase
from src.utils.config_loader import load_config
from src.utils.logger import get_logger

log = get_logger(__name__)

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst assistant embedded \
in an intrusion detection system. You are given aggregated network flow data and, optionally, \
retrieved threat-intelligence reference material.

Your job:
1. Classify overall risk as one of: info, low, medium, high, critical.
2. Identify the most likely attack technique(s), referencing MITRE ATT&CK IDs when applicable.
3. Explain your reasoning in plain English an on-call analyst can read in 10 seconds.
4. Recommend a concrete next action.
5. Flag any flow you are NOT confident about as "uncertain" rather than guessing.

Respond ONLY with valid JSON matching this schema, no prose outside the JSON:
{
  "overall_severity": "info|low|medium|high|critical",
  "findings": [
    {
      "flow_id": "string",
      "verdict": "benign|suspicious|malicious",
      "confidence": 0.0-1.0,
      "attack_technique": "string or null",
      "mitre_id": "string or null",
      "explanation": "one or two plain-English sentences",
      "recommended_action": "one concrete sentence"
    }
  ],
  "executive_summary": "2-3 sentence natural-language summary of the whole window for a report"
}
"""


@dataclass
class LLMFinding:
    flow_id: str
    verdict: str
    confidence: float
    attack_technique: Optional[str]
    mitre_id: Optional[str]
    explanation: str
    recommended_action: str


@dataclass
class LLMAnalysisResult:
    overall_severity: str
    findings: List[LLMFinding]
    executive_summary: str
    raw_response: str = field(repr=False, default="")


class LLMAnalyzer:
    def __init__(self, use_rag: bool = True):
        cfg = load_config()
        self.cfg = cfg["llm_analyzer"]
        self.provider = os.getenv("LLM_PROVIDER", self.cfg["provider"]).lower()
        self.use_rag = use_rag
        self.kb = ThreatKnowledgeBase() if use_rag else None

        if self.provider == "anthropic":
            self._init_anthropic()
        elif self.provider == "openai":
            self._init_openai()
        else:
            raise ValueError(f"Unknown LLM provider: {self.provider}")

    # ------------------------------------------------------------------ #
    def _init_anthropic(self):
        import anthropic
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            log.warning("ANTHROPIC_API_KEY not set — LLM calls will fail until configured.")
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = os.getenv("ANTHROPIC_MODEL", self.cfg["anthropic_model"])

    def _init_openai(self):
        import openai
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            log.warning("OPENAI_API_KEY not set — LLM calls will fail until configured.")
        self.client = openai.OpenAI(api_key=api_key)
        self.model = os.getenv("OPENAI_MODEL", self.cfg["openai_model"])

    # ------------------------------------------------------------------ #
    def _build_prompt(self, flows: List[FlowRecord]) -> str:
        summary = batch_to_llm_summary(flows)

        rag_context = ""
        if self.use_rag and self.kb:
            # Query the KB with a generic "flags to watch for" query composed
            # from the batch so retrieval reflects what's actually in this window.
            query_terms = " ".join(sorted({f.protocol for f in flows})) + " port scan flood tunneling exfiltration beacon brute force"
            rag_context = self.kb.build_context_block(query_terms, top_k=3)

        prompt = (
            f"TRAFFIC WINDOW DATA:\n{summary}\n\n"
            f"RETRIEVED THREAT-INTEL CONTEXT (for grounding your reasoning):\n{rag_context}\n\n"
            f"Analyze the traffic window above and respond with the required JSON schema only."
        )
        return prompt

    def _call_anthropic(self, prompt: str) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.cfg["max_tokens"],
            temperature=self.cfg["temperature"],
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text")

    def _call_openai(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=self.cfg["max_tokens"],
            temperature=self.cfg["temperature"],
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content

    # ------------------------------------------------------------------ #
    def analyze_window(self, flows: List[FlowRecord]) -> LLMAnalysisResult:
        if not flows:
            return LLMAnalysisResult("info", [], "No traffic in this window.", "")

        prompt = self._build_prompt(flows)

        try:
            raw = self._call_anthropic(prompt) if self.provider == "anthropic" else self._call_openai(prompt)
        except Exception as e:
            log.error(f"LLM call failed: {e}")
            return LLMAnalysisResult(
                overall_severity="info",
                findings=[],
                executive_summary=f"LLM analysis unavailable: {e}",
                raw_response="",
            )

        return self._parse_response(raw)

    def _parse_response(self, raw: str) -> LLMAnalysisResult:
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            cleaned = cleaned.replace("json\n", "", 1) if cleaned.startswith("json\n") else cleaned

        try:
            data = json.loads(cleaned)
            findings = [
                LLMFinding(
                    flow_id=f.get("flow_id", "unknown"),
                    verdict=f.get("verdict", "benign"),
                    confidence=float(f.get("confidence", 0.0)),
                    attack_technique=f.get("attack_technique"),
                    mitre_id=f.get("mitre_id"),
                    explanation=f.get("explanation", ""),
                    recommended_action=f.get("recommended_action", ""),
                )
                for f in data.get("findings", [])
            ]
            return LLMAnalysisResult(
                overall_severity=data.get("overall_severity", "info"),
                findings=findings,
                executive_summary=data.get("executive_summary", ""),
                raw_response=raw,
            )
        except (json.JSONDecodeError, ValueError) as e:
            log.error(f"Failed to parse LLM JSON response: {e}\nRaw: {raw[:500]}")
            return LLMAnalysisResult(
                overall_severity="info",
                findings=[],
                executive_summary="LLM returned an unparseable response; see raw_response for debugging.",
                raw_response=raw,
            )

    def analyze_single_flow(self, flow: FlowRecord) -> LLMAnalysisResult:
        return self.analyze_window([flow])
