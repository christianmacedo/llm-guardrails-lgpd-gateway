import re
from typing import Dict, Any
from pydantic import BaseModel

class SecurityAuditResult(BaseModel):
    is_safe: bool
    sanitized_prompt: str
    redacted_entities: list[str]
    blocked_reason: str | None = None

class LGPDGuardrailGateway:
    """Enterprise middleware for PII redaction (LGPD/GDPR) and Prompt Injection defense."""

    PII_PATTERNS = {
        "CPF": r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b",
        "CNPJ": r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b",
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "PHONE_BR": r"\b(?:\+55\s?)?(?:\(?\d{2}\)?\s?)?\d{4,5}-?\d{4}\b",
    }

    INJECTION_SIGNATURES = [
        r"ignore (all )?(previous|prior) instructions",
        r"system prompt",
        r"you are now in developer mode",
        r"bypass (security|guardrails|filters)",
    ]

    def inspect_and_sanitize(self, user_input: str) -> SecurityAuditResult:
        for pattern in self.INJECTION_SIGNATURES:
            if re.search(pattern, user_input, re.IGNORECASE):
                return SecurityAuditResult(
                    is_safe=False,
                    sanitized_prompt="",
                    redacted_entities=[],
                    blocked_reason="Adversarial Prompt Injection detected."
                )

        sanitized = user_input
        detected_pii = []

        for entity_type, regex in self.PII_PATTERNS.items():
            if re.search(regex, sanitized):
                detected_pii.append(entity_type)
                sanitized = re.sub(regex, f"[REDACTED_{entity_type}]", sanitized)

        return SecurityAuditResult(
            is_safe=True,
            sanitized_prompt=sanitized,
            redacted_entities=detected_pii
        )

def langgraph_security_node(state: Dict[str, Any]) -> Dict[str, Any]:
    gateway = LGPDGuardrailGateway()
    audit = gateway.inspect_and_sanitize(state.get("user_message", ""))
    if not audit.is_safe:
        raise ValueError(f"Security Policy Violation: {audit.blocked_reason}")
    return {
        **state,
        "sanitized_message": audit.sanitized_prompt,
        "lgpd_audit_log": audit.redacted_entities
    }
