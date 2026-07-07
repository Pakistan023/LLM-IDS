"""
NLP Alert Summarizer (bonus feature).

Takes a batch of raw alerts (from AlertStore) covering some time range and
asks the LLM to produce a single, concise shift-handoff style digest —
the kind of "what happened while you were out" report a SOC lead reads at
the start of a shift, rather than scrolling through hundreds of raw rows.
"""

import os
from typing import List

from src.utils.config_loader import load_config
from src.utils.logger import get_logger

log = get_logger(__name__)

DIGEST_SYSTEM_PROMPT = """You are writing a concise SOC shift-handoff digest from a list of raw \
intrusion-detection alerts. Group related alerts, avoid repeating near-duplicates, prioritize by \
severity, and write for a human analyst who has 60 seconds to read this before their shift. \
Use short paragraphs and bullet points. Do not invent facts not present in the alert data."""


class AlertSummarizer:
    def __init__(self):
        cfg = load_config()
        self.provider = os.getenv("LLM_PROVIDER", cfg["llm_analyzer"]["provider"]).lower()

        if self.provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
            self.model = os.getenv("ANTHROPIC_MODEL", cfg["llm_analyzer"]["anthropic_model"])
        else:
            import openai
            self.client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            self.model = os.getenv("OPENAI_MODEL", cfg["llm_analyzer"]["openai_model"])

    def _format_alerts(self, alerts: List[dict]) -> str:
        lines = []
        for a in alerts:
            lines.append(
                f"- [{a.get('severity','?')}] detector={a.get('detector')} "
                f"{a.get('src_ip')} -> {a.get('dst_ip')}:{a.get('dst_port')} "
                f"technique={a.get('technique')} conf={a.get('confidence')} "
                f"note={a.get('explanation')}"
            )
        return "\n".join(lines)

    def summarize(self, alerts: List[dict]) -> str:
        if not alerts:
            return "No alerts recorded in this period — clean shift."

        alert_text = self._format_alerts(alerts)
        prompt = f"RAW ALERTS ({len(alerts)} total):\n{alert_text}\n\nWrite the shift digest now."

        try:
            if self.provider == "anthropic":
                response = self.client.messages.create(
                    model=self.model, max_tokens=700, temperature=0.3,
                    system=DIGEST_SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}],
                )
                return "".join(b.text for b in response.content if b.type == "text")
            else:
                response = self.client.chat.completions.create(
                    model=self.model, max_tokens=700, temperature=0.3,
                    messages=[
                        {"role": "system", "content": DIGEST_SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                )
                return response.choices[0].message.content
        except Exception as e:
            log.error(f"Digest generation failed: {e}")
            return f"(Digest unavailable — LLM call failed: {e})\n\nRaw alert count: {len(alerts)}"
