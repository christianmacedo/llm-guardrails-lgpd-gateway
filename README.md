# Enterprise LLM Guardrails & LGPD Security Gateway

Security and governance middleware for production LLM applications and Autonomous Agents. Enforces **LGPD/GDPR data privacy (PII masking)** and **Prompt Injection defense** before routing requests to **Vertex AI / Gemini** via **LangGraph**.

## Core Capabilities
- **PII Detection & Masking (LGPD/GDPR):** Automatically redacts CPF, CNPJ, emails, phone numbers, and financial data prior to LLM inference.
- **Prompt Injection & Jailbreak Defense:** Heuristic and semantic input validation blocking adversarial system prompt overrides.
- **Output Guardrails:** Validates structured agent outputs and prevents sensitive data leakage.
