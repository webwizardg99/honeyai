# HoneyAI 🍯🤖

AI-powered SSH honeypot response generator. Uses a local LLM (via Ollama) to generate realistic, contextual Linux shell responses for every attacker command — making the honeypot indistinguishable from a real server.

## Features

- **LLM-generated responses** — every shell command gets a realistic, context-aware reply
- **Fake Linux profile** — configurable hostname, filesystem, fake secrets (`.env`, `wp-config.php`)
- **TTP detection** — automatically classifies attacker techniques (recon, privesc, lateral movement...)
- **SENTINEL integration** — logs TTP events to the honeypot aggregator
- **ATLAS integration** — maps detected TTPs to MITRE ATT&CK framework
- **Cowrie backend** — drop-in LLM backend for Cowrie SSH honeypot

## Architecture

```
Attacker SSH → Cowrie → HoneyAI API → Ollama LLM → realistic shell output
                                    ↓
                              TTP Detection → SENTINEL + ATLAS
```

## Quick Start

```bash
# Install dependencies
pip3 install aiohttp openai

# Configure Ollama model
export HONEYAI_MODEL=llama3:8b   # or any model on your Ollama instance

# Start
python3 honeyai_agent.py
```

## API

```
POST /cmd       {session_id, command, attacker_ip} → {output, ttps_detected, alert}
GET  /sessions  — active attacker sessions with TTP summary
GET  /health
GET  /test?cmd=whoami
```

## Cowrie Integration

```ini
# cowrie/etc/cowrie.cfg
[llm]
enabled = true
backend = llm
host = http://127.0.0.1:8191
```

## Victim Profile

Edit `victim_profile.json` to customize the fake server identity:
- Hostname, OS version
- Fake filesystem entries
- Embedded fake secrets

## Requirements

- Python 3.10+
- Ollama running locally or on a remote host
- Optional: Cowrie SSH honeypot, SENTINEL, ATLAS

## License

MIT
