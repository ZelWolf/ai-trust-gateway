import asyncio
from typing import Dict, Any, List, Tuple
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern

class DeterministicEngine:
    def __init__(self):
        self.analyzer = AnalyzerEngine()
        
        # Custom regex patterns for credentials and specific PII
        self.custom_patterns = {
            # Secrets & Tokens
            "AWS_ACCESS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
            "OPENAI_API_KEY": r"\bsk-[A-Za-z0-9_-]{20,}\b",
            "JWT_TOKEN": r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b",
            "RSA_PRIVATE_KEY": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
            "US_SSN_PATTERN": r"\b\d{3}-\d{2}-\d{4}\b",
            "DRIVERS_LICENSE": r"\bDL\d{8}\b",
            "OBFUSCATED_ID": r"(?i)\b(?:(?:zero|one|two|three|four|five|six|seven|eight|nine|oh|\d)[,\s-]*){8,12}\b",
            "STREET_ADDRESS": r"(?i)\b\d{1,6}\s+(?:[A-Za-z0-9#-]+\s+){1,5}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Square|Sq|Place|Pl|Terrace|Parkway|Pkwy|Circle|Cir)\b",
            
            # Indian PII 
            "PAN_NUMBER": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
            "AADHAAR_NUMBER": r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b",
            
        }
        self._init_custom_recognizers()

    def _init_custom_recognizers(self):
        for name, pattern_str in self.custom_patterns.items():
            pattern = Pattern(name=f"{name}_pattern", regex=pattern_str, score=0.85)
            recognizer = PatternRecognizer(
                supported_entity=name, 
                patterns=[pattern],
                context=["pan", "income tax", "aadhaar", "uidai", "identity", "card", "key", "token"]
            )
            self.analyzer.registry.add_recognizer(recognizer)

    def _sync_scan_and_redact(self, text: str) -> Tuple[str, List[Dict[str, Any]], float]:
        """Synchronous CPU-bound work isolated here"""
        if not text.strip():
            return text, [], 0.0

        # Enable Presidio built-ins alongside custom recognizers
        target_entities = [
            "EMAIL_ADDRESS", 
            "PHONE_NUMBER", 
            "CREDIT_CARD", 
            "US_SSN", 
            "IP_ADDRESS",
            "IBAN_CODE"
        ] + list(self.custom_patterns.keys())
        
        results = self.analyzer.analyze(text=text, language="en", entities=target_entities)

        # Sort primarily by start index (reverse) and secondarily by score (highest first)
        sorted_results = sorted(results, key=lambda x: (x.start, x.score), reverse=True)
        
        detected_items = []
        modified_text = text
        risk_score = 0.0

        high_risk_prefixes = ("KEY", "TOKEN", "PRIVATE_KEY", "CARD", "SSN", "AADHAAR", "PAN")

        # Track the start index of the last processed redaction to prevent collision
        last_processed_start = float('inf')

        for res in sorted_results:
            # If current match overlaps with the previously processed string space, skip it
            if res.end > last_processed_start:
                continue
            
            # Lock in the new boundary
            last_processed_start = res.start

            is_high_risk = any(tag in res.entity_type for tag in high_risk_prefixes)
            weight = 40.0 if is_high_risk else 15.0
            risk_score += weight
            
            detected_items.append({
                "entity": res.entity_type, 
                "range": [res.start, res.end],
                "score": round(res.score, 2)
            })
            
            # Safely slice and redact
            modified_text = modified_text[:res.start] + f"[{res.entity_type}_REDACTED]" + modified_text[res.end:]

        return modified_text, detected_items, min(risk_score, 100.0)

    async def scan_and_redact(self, text: str) -> Tuple[str, List[Dict[str, Any]], float]:
        """Asynchronous wrapper to prevent blocking the FastAPI event loop"""
        return await asyncio.to_thread(self._sync_scan_and_redact, text)