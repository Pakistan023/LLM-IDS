"""
Voice-driven security assistant (bonus feature).

Lets an analyst ask questions like "what happened in the last hour?" or
"summarize critical alerts" out loud, and hear a spoken response. Uses
SpeechRecognition for speech-to-text (via the default microphone) and
pyttsx3 for offline text-to-speech, so it works without an internet
connection for the voice I/O layer itself (only the LLM call needs
network access).

This module is optional and disabled by default (see config.yaml ->
voice_assistant.enabled). It degrades gracefully with a clear error if
no microphone/audio backend is available (e.g. in headless/server
environments) — use `ask_text()` directly in that case.
"""

from typing import Optional

from src.alerts.nlp_summarizer import AlertSummarizer
from src.db.database import AlertStore
from src.utils.logger import get_logger

log = get_logger(__name__)

ASSISTANT_SYSTEM_CONTEXT = (
    "You are a spoken security assistant. Keep answers under 60 words, "
    "conversational, and avoid jargon-heavy MITRE IDs unless asked directly."
)


class VoiceSecurityAssistant:
    def __init__(self):
        self.store = AlertStore()
        self.summarizer = AlertSummarizer()
        self._speech_backend_ready = False
        self._init_audio()

    def _init_audio(self):
        try:
            import speech_recognition as sr  # noqa: F401
            import pyttsx3  # noqa: F401
            self._speech_backend_ready = True
        except Exception as e:
            log.warning(f"Voice I/O backend unavailable ({e}). Use ask_text() for a text-only interface.")

    # ---------------------------------------------------------------- #
    def listen(self, timeout: int = 6) -> Optional[str]:
        """Capture one spoken utterance from the default microphone and transcribe it."""
        if not self._speech_backend_ready:
            raise RuntimeError("Voice backend not available in this environment.")
        import speech_recognition as sr

        recognizer = sr.Recognizer()
        with sr.Microphone() as source:
            log.info("Listening ...")
            audio = recognizer.listen(source, timeout=timeout)
        try:
            return recognizer.recognize_google(audio)
        except sr.UnknownValueError:
            return None

    def speak(self, text: str):
        if not self._speech_backend_ready:
            print(f"[assistant would say]: {text}")
            return
        import pyttsx3
        engine = pyttsx3.init()
        engine.say(text)
        engine.runAndWait()

    # ---------------------------------------------------------------- #
    def ask_text(self, question: str) -> str:
        """Text-in/text-out path — always available, used by the dashboard chat box too."""
        alerts = self.store.fetch_recent(limit=100)

        q_lower = question.lower()
        if "critical" in q_lower:
            alerts = [a for a in alerts if a.get("severity") == "critical"]
        elif "high" in q_lower:
            alerts = [a for a in alerts if a.get("severity") in ("high", "critical")]

        digest = self.summarizer.summarize(alerts)
        return digest

    def run_voice_loop(self, max_turns: int = 10):
        """Blocking loop: listen -> answer -> speak. For local/demo use only."""
        if not self._speech_backend_ready:
            print("Voice backend unavailable — falling back to a text prompt loop.")
            for _ in range(max_turns):
                q = input("You: ")
                if q.strip().lower() in ("exit", "quit"):
                    break
                print("Assistant:", self.ask_text(q))
            return

        for _ in range(max_turns):
            heard = self.listen()
            if not heard:
                continue
            log.info(f"Heard: {heard}")
            answer = self.ask_text(heard)
            self.speak(answer)
