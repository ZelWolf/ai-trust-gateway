import asyncio
from typing import Dict, Any, List, Tuple
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern

class DeterministicEngine:
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        
        # Regex patterns for detecting specific secrets
        self.secret_patterns = {
            "AWS_ACCESS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
            "OPENAI_API_KEY": r"\bsk-[A-Za-z0-9_-]{20,}\b",
        }
        self._init_custom_recognizers()

    def _init_custom_recognizers(self):
        for name, pattern_str in self.secret_patterns.items():
            pattern = Pattern(name=f"{name}_pattern", regex=pattern_str, score=0.95)
            recognizer = PatternRecognizer(supported_entity=name, patterns=[pattern])
            self.analyzer.registry.add_recognizer(recognizer)

    def _sync_scan_and_redact(self, text: str) -> Tuple[str, List[Dict[str, Any]], float]:
        """Synchronous CPU-bound work isolated here"""
        if not text.strip():
            return text, [], 0.0

        target_entities = ["EMAIL_ADDRESS", "PHONE_NUMBER"] + list(self.secret_patterns.keys())
        results = self.analyzer.analyze(text=text, language="en", entities=target_entities)

        sorted_results = sorted(results, key=lambda x: x.start, reverse=True)
        detected_items = []
        modified_text = text
        risk_score = 0.0

        for res in sorted_results:
            weight = 40.0 if "KEY" in res.entity_type else 15.0
            risk_score += weight
            detected_items.append({"entity": res.entity_type, "range": [res.start, res.end]})
            modified_text = modified_text[:res.start] + f"[{res.entity_type}_REDACTED]" + modified_text[res.end:]

        return modified_text, detected_items, min(risk_score, 100.0)

    async def scan_and_redact(self, text: str) -> Tuple[str, List[Dict[str, Any]], float]:
        """Asynchronous wrapper to prevent blocking the FastAPI event loop"""
        return await asyncio.to_thread(self._sync_scan_and_redact, text)