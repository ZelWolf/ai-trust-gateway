import re
from typing import Dict, Any, List, Tuple
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern

class DeterministicEngine:
    def __init__(self):
        # Initializing Presidio with the NLP
        self.analyzer = AnalyzerEngine()
        
        #Regex Patterns
        self.secret_patterns = {
            "AWS_SECRET_KEY": r"(?i)aws_(?:secret|access)_key(?:_id)?.*?['\"]?([A-Za-z0-9/+=]{20,40})['\"]?",
            "OPENAI_API_KEY": r"sk-[a-zA-Z0-9]{32,48}"
        }
        self._init_custom_recognizers()

    def _init_custom_recognizers(self):
        """Register our custom regex patterns with Presidio."""
        for entity_name, pattern_str in self.secret_patterns.items():
            pattern = Pattern(name=f"{entity_name}_pattern", regex=pattern_str, score=0.95)
            recognizer = PatternRecognizer(
                supported_entity=entity_name, 
                patterns=[pattern]
            )
            self.analyzer.registry.add_recognizer(recognizer)

    def scan_and_redact(self, text: str) -> Tuple[str, List[Dict[str, Any]], float]:
        """Scans text, extracts PII/Secrets, and redacts them."""
        if not text.strip():
            return text, [], 0.0

        # Entities we care about today
        target_entities = ["EMAIL_ADDRESS", "PHONE_NUMBER"] + list(self.secret_patterns.keys())
        
        results = self.analyzer.analyze(
            text=text, 
            language="en", 
            entities=target_entities
        )

        # Sort backwards so string indices don't break when we replace text
        sorted_results = sorted(results, key=lambda x: x.start, reverse=True)
        
        detected_items = []
        modified_text = text
        risk_score = 0.0

        for res in sorted_results:
            entity_type = res.entity_type
            
            # Penalizing based on type
            weight = 40.0 if "KEY" in entity_type else 15.0
            risk_score += weight

            detected_items.append({
                "entity": entity_type,
                "range": [res.start, res.end]
            })

            # Replace the sensitive data with a placeholder
            modified_text = modified_text[:res.start] + f"[{entity_type}_REDACTED]" + modified_text[res.end:]

        return modified_text, detected_items, min(risk_score, 100.0)