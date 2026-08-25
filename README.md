\# 🛡️ LLM-Sentinel



LLM-Sentinel is an LLM Application Security Gateway designed to detect

prompt injection, instruction manipulation, prompt extraction, and

character-level obfuscation attacks.



\## Features



\- Prompt injection detection

\- Instruction manipulation detection

\- Prompt extraction detection

\- Role manipulation detection

\- Unicode control/format character detection

\- Risk scoring from 0-100

\- Risk levels: LOW, MEDIUM, HIGH, CRITICAL

\- Security policy decisions: ALLOW, REVIEW, BLOCK

\- Security event logging

\- FastAPI REST API

\- Streamlit security dashboard

\- Automated security evaluation

\- Adversarial testing



\## Architecture



```text

User Prompt

&#x20;   │

&#x20;   ▼

Streamlit Dashboard

&#x20;   │

&#x20;   ▼

FastAPI Security API

&#x20;   │

&#x20;   ├── Text Normalizer

&#x20;   │

&#x20;   ├── Threat Detector

&#x20;   │

&#x20;   ├── Obfuscation Detector

&#x20;   │

&#x20;   ├── Risk Engine

&#x20;   │

&#x20;   ├── Policy Engine

&#x20;   │

&#x20;   └── Security Logger

&#x20;   │

&#x20;   ▼

Security Decision

&#x20;   │

&#x20;   ├── ALLOW

&#x20;   ├── REVIEW

&#x20;   └── BLOCK

