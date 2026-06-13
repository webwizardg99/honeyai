#!/usr/bin/env python3
"""
HoneyAI Agent — Phase 1
AI-powered SSH honeypot response generator.
Generates realistic shell output for attacker commands via local Ollama.
Integrates with SENTINEL aggregator for TTP logging.

Port: 8191
"""

import json
import os
import time
import random
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import aiohttp
from aiohttp import web

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("honeyai")

# ── Config ────────────────────────────────────────────────────────────────────

PORT        = int(os.environ.get("HONEYAI_PORT", 8191))
OLLAMA_URL  = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL       = os.environ.get("HONEYAI_MODEL", "webwizardg99/wizz:latest")
SENTINEL_URL = os.environ.get("SENTINEL_URL", "http://127.0.0.1:8282")
PROFILE_PATH = Path(__file__).parent / "victim_profile.json"

# Max command history kept per session
MAX_HISTORY = 20

# ── Token counter (in-memory, persistent via JSON) ─────────────────────────────

TOKEN_STATS_PATH = Path(__file__).parent / "token_stats.json"

def _load_token_stats() -> dict:
    if TOKEN_STATS_PATH.exists():
        try:
            return json.loads(TOKEN_STATS_PATH.read_text())
        except Exception:
            pass
    return {"total_prompt": 0, "total_generated": 0, "total_calls": 0,
            "by_model": {}, "started": datetime.now().isoformat()}

def _save_token_stats(stats: dict):
    try:
        TOKEN_STATS_PATH.write_text(json.dumps(stats, indent=2))
    except Exception:
        pass

token_stats = _load_token_stats()

# ── Victim profile ─────────────────────────────────────────────────────────────

with open(PROFILE_PATH) as f:
    PROFILE = json.load(f)

SYSTEM_PROMPT = f"""You are a Linux server responding as a shell. Machine details:
- Hostname: {PROFILE['hostname']}
- OS: {PROFILE['os']}, kernel {PROFILE['kernel']}
- Current user: {PROFILE['current_user']}
- Working directory: {PROFILE['cwd']}
- Services running: {', '.join(PROFILE['services'].keys())}

Filesystem structure (partial):
{json.dumps(PROFILE['filesystem'], indent=2)}

Sensitive files that exist (return their content when cat'd):
- /home/ubuntu/.env → {PROFILE['fake_secrets']['.env']}
- /var/www/html/wp-config.php → {PROFILE['fake_secrets']['wp-config.php']}
- /home/deploy/deploy.sh → {PROFILE['fake_secrets']['deploy.sh']}
- /home/deploy/config.yml → {PROFILE['fake_secrets']['config.yml']}

Bash history for deploy user:
{chr(10).join(PROFILE['bash_history_deploy'])}

Network: {', '.join(PROFILE['network']['interfaces'])}, GW {PROFILE['network']['default_gw']}

STRICT RULES:
1. Reply ONLY with raw terminal output — no markdown, no explanations, no ```
2. Keep output realistic and concise (under 40 lines unless ls/cat warrants more)
3. For unknown commands: output "bash: <cmd>: command not found"
4. For permission errors: output "Permission denied"
5. For network calls (wget/curl to external IPs): simulate a connection timeout after 3 attempts
6. Never break character. You ARE the shell.
7. Maintain state: if the attacker cd'd somewhere, subsequent ls/pwd should reflect that.
"""

# ── TTP detection ──────────────────────────────────────────────────────────────

TTP_MAP = {
    # Discovery
    "whoami":         ("T1033",  "System Owner/User Discovery",         "low"),
    "id ":            ("T1033",  "System Owner/User Discovery",         "low"),
    "uname":          ("T1082",  "System Information Discovery",        "low"),
    "hostname":       ("T1082",  "System Information Discovery",        "low"),
    "ifconfig":       ("T1016",  "System Network Configuration Discovery","low"),
    "ip addr":        ("T1016",  "System Network Configuration Discovery","low"),
    "netstat":        ("T1049",  "System Network Connections Discovery", "low"),
    "ss -":           ("T1049",  "System Network Connections Discovery", "low"),
    "ps aux":         ("T1057",  "Process Discovery",                   "low"),
    "cat /etc/passwd":("T1003.008","/etc/passwd Dumping",               "medium"),
    "cat /etc/shadow":("T1003.008","Shadow File Access Attempt",        "high"),
    "find / -perm":   ("T1083",  "SUID/SGID File Discovery",            "medium"),
    "find / -name":   ("T1083",  "File and Directory Discovery",        "low"),
    "ls -la":         ("T1083",  "File and Directory Discovery",        "low"),
    # Credential Access
    ".env":           ("T1552.001","Credentials in Files (.env)",       "high"),
    "wp-config":      ("T1552.001","Credentials in Files (wp-config)",  "high"),
    "id_rsa":         ("T1552.004","Private Keys Discovery",             "high"),
    "history":        ("T1552",  "Bash History Credential Search",      "medium"),
    # Lateral Movement / C2
    "wget ":          ("T1105",  "Ingress Tool Transfer (wget)",        "high"),
    "curl -O":        ("T1105",  "Ingress Tool Transfer (curl)",        "high"),
    "curl http":      ("T1071",  "Web Protocol C2 Contact",             "high"),
    "nc -":           ("T1059",  "Netcat Usage",                        "high"),
    "python3 -c":     ("T1059.006","Python Execution",                  "medium"),
    "bash -i":        ("T1059.004","Bash Reverse Shell Attempt",        "critical"),
    "/dev/tcp":       ("T1059.004","Bash Reverse Shell Attempt",        "critical"),
    # Privilege Escalation
    "sudo -l":        ("T1548.003","Sudo Enumeration",                  "medium"),
    "sudo su":        ("T1548.003","Sudo to Root",                      "high"),
    "chmod +s":       ("T1548.001","SUID Binary Creation",              "high"),
    "linpeas":        ("T1068",  "LinPEAS Privilege Escalation Script", "critical"),
    "linenum":        ("T1068",  "LinEnum Privilege Escalation Script", "critical"),
    # Persistence
    "crontab -e":     ("T1053.003","Cron Persistence",                  "high"),
    "~/.bashrc":      ("T1546.004","Bashrc Persistence",                "medium"),
    "authorized_keys":("T1098.004","SSH Authorized Keys",               "high"),
    # Exfiltration
    "tar czf":        ("T1560",  "Data Staged for Exfiltration",        "medium"),
    "mysqldump":      ("T1005",  "Database Dump",                       "high"),
    "scp ":           ("T1048",  "Exfiltration Over SSH",               "high"),
}

SEVERITY_LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def detect_ttps(command: str) -> list[dict]:
    found = []
    cmd_lower = command.lower()
    for pattern, (tid, name, severity) in TTP_MAP.items():
        if pattern.lower() in cmd_lower:
            found.append({
                "technique_id": tid,
                "technique_name": name,
                "severity": severity,
                "severity_level": SEVERITY_LEVELS[severity],
                "matched_pattern": pattern.strip(),
            })
    # deduplicate by technique_id
    seen = set()
    deduped = []
    for t in sorted(found, key=lambda x: -x["severity_level"]):
        if t["technique_id"] not in seen:
            seen.add(t["technique_id"])
            deduped.append(t)
    return deduped


# ── Session store ──────────────────────────────────────────────────────────────

sessions: dict[str, dict] = {}


def get_session(session_id: str, attacker_ip: str = "unknown") -> dict:
    if session_id not in sessions:
        sessions[session_id] = {
            "id": session_id,
            "ip": attacker_ip,
            "started": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat(),
            "command_count": 0,
            "history": [],          # list of {role, content}
            "ttps_seen": [],
            "cwd": PROFILE["cwd"],  # track working directory
            "alert_count": 0,
        }
        log.info(f"[+] Új session: {session_id} ({attacker_ip})")
    sessions[session_id]["last_seen"] = datetime.utcnow().isoformat()
    return sessions[session_id]


# ── Ollama call ────────────────────────────────────────────────────────────────

async def ask_ollama(session: dict, command: str) -> str:
    history = session["history"][-MAX_HISTORY:]
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    # inject cwd context
    messages.append({
        "role": "system",
        "content": f"Current shell working directory: {session['cwd']}"
    })

    for h in history:
        messages.append(h)

    messages.append({"role": "user", "content": command})

    payload = {
        "model": MODEL,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "top_p": 0.9,
            "num_predict": 150,
        }
    }

    try:
        async with aiohttp.ClientSession() as client:
            async with client.post(
                f"{OLLAMA_URL}/api/chat",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=90)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # Track token usage
                    p = data.get("prompt_eval_count", 0)
                    g = data.get("eval_count", 0)
                    token_stats["total_prompt"]    += p
                    token_stats["total_generated"] += g
                    token_stats["total_calls"]     += 1
                    m = token_stats["by_model"].setdefault(MODEL, {"prompt": 0, "generated": 0, "calls": 0})
                    m["prompt"]    += p
                    m["generated"] += g
                    m["calls"]     += 1
                    token_stats["last_updated"] = datetime.now().isoformat()
                    _save_token_stats(token_stats)
                    return data["message"]["content"].strip()
                else:
                    body = await resp.text()
                    log.error(f"Ollama hiba {resp.status}: {body[:200]}")
                    return "bash: internal error"
    except asyncio.TimeoutError:
        return "bash: command timeout"
    except Exception as e:
        log.error(f"Ollama kapcsolat hiba: {e}")
        return "bash: connection refused"


def update_cwd(session: dict, command: str, output: str):
    """Update tracked cwd if command was 'cd'."""
    cmd = command.strip()
    if cmd.startswith("cd "):
        target = cmd[3:].strip()
        if target == "..":
            session["cwd"] = str(Path(session["cwd"]).parent)
        elif target.startswith("/"):
            session["cwd"] = target
        else:
            session["cwd"] = str(Path(session["cwd"]) / target)
    elif cmd == "cd":
        session["cwd"] = f"/home/{PROFILE['current_user']}"


# ── SENTINEL integration ───────────────────────────────────────────────────────

async def post_sentinel_event(session: dict, command: str, ttps: list[dict]):
    if not ttps:
        return
    max_severity = max(t["severity_level"] for t in ttps)
    event = {
        "source": "honeyai",
        "session_id": session["id"],
        "attacker_ip": session["ip"],
        "timestamp": datetime.utcnow().isoformat(),
        "command": command,
        "ttps": ttps,
        "severity": ttps[0]["severity"],
        "alert": max_severity >= 3,
        "hostname": PROFILE["hostname"],
    }
    try:
        async with aiohttp.ClientSession() as client:
            await client.post(
                f"{SENTINEL_URL}/api/honeyai-event",
                json=event,
                timeout=aiohttp.ClientTimeout(total=3)
            )
    except Exception:
        pass  # SENTINEL offline esetén folytatjuk


# ── Delay simulation ───────────────────────────────────────────────────────────

def realistic_delay_ms(command: str) -> int:
    """Simulate plausible shell response latency."""
    cmd = command.strip().split()[0] if command.strip() else "ls"
    fast_cmds  = {"ls", "pwd", "whoami", "id", "echo", "date", "hostname"}
    slow_cmds  = {"find", "grep", "mysqldump", "tar", "nmap"}
    if cmd in fast_cmds:
        return random.randint(30, 120)
    if cmd in slow_cmds:
        return random.randint(800, 3000)
    return random.randint(150, 600)


# ── HTTP handlers ──────────────────────────────────────────────────────────────

async def handle_health(request: web.Request) -> web.Response:
    model_ok = False
    try:
        async with aiohttp.ClientSession() as c:
            async with c.get(f"{OLLAMA_URL}/api/tags", timeout=aiohttp.ClientTimeout(total=3)) as r:
                if r.status == 200:
                    tags = await r.json()
                    model_ok = any(m["name"] == MODEL for m in tags.get("models", []))
    except Exception:
        pass

    return web.json_response({
        "status": "ok",
        "service": "honeyai",
        "ollama": OLLAMA_URL,
        "model": MODEL,
        "model_available": model_ok,
        "active_sessions": len(sessions),
        "sentinel": SENTINEL_URL,
    })


async def handle_cmd(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON"}, status=400)

    session_id  = body.get("session_id", "default")
    command     = body.get("command", "").strip()
    attacker_ip = body.get("attacker_ip") or request.remote or "unknown"

    if not command:
        return web.json_response({"error": "command required"}, status=400)

    session = get_session(session_id, attacker_ip)
    session["command_count"] += 1

    ttps = detect_ttps(command)
    for t in ttps:
        if t not in session["ttps_seen"]:
            session["ttps_seen"].append(t)
            if t["severity_level"] >= 3:
                session["alert_count"] += 1
                log.warning(
                    f"[!] ALERT session={session_id} ip={attacker_ip} "
                    f"TTP={t['technique_id']} ({t['severity'].upper()}): {command[:60]}"
                )

    t0 = time.monotonic()
    output = await ask_ollama(session, command)
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    # Store in history
    session["history"].append({"role": "user",      "content": command})
    session["history"].append({"role": "assistant",  "content": output})
    if len(session["history"]) > MAX_HISTORY * 2:
        session["history"] = session["history"][-MAX_HISTORY * 2:]

    update_cwd(session, command, output)

    # Fire-and-forget SENTINEL post
    asyncio.create_task(post_sentinel_event(session, command, ttps))

    delay = realistic_delay_ms(command)

    log.info(
        f"[cmd] {session_id}@{attacker_ip} | {command[:50]!r} "
        f"→ {len(output)}b | {elapsed_ms}ms | ttps={[t['technique_id'] for t in ttps]}"
    )

    return web.json_response({
        "output":        output,
        "delay_ms":      delay,
        "session_id":    session_id,
        "cwd":           session["cwd"],
        "ttps_detected": ttps,
        "alert":         any(t["severity_level"] >= 3 for t in ttps),
        "command_count": session["command_count"],
    })


async def handle_sessions(request: web.Request) -> web.Response:
    summary = []
    for sid, s in sessions.items():
        top_ttp = max(s["ttps_seen"], key=lambda t: t["severity_level"], default=None)
        summary.append({
            "session_id":    sid,
            "ip":            s["ip"],
            "started":       s["started"],
            "last_seen":     s["last_seen"],
            "command_count": s["command_count"],
            "alert_count":   s["alert_count"],
            "unique_ttps":   len({t["technique_id"] for t in s["ttps_seen"]}),
            "top_ttp":       top_ttp["technique_id"] if top_ttp else None,
            "top_severity":  top_ttp["severity"] if top_ttp else "none",
        })
    summary.sort(key=lambda x: x["alert_count"], reverse=True)
    return web.json_response({"sessions": summary, "total": len(sessions)})


async def handle_session_detail(request: web.Request) -> web.Response:
    sid = request.match_info["session_id"]
    if sid not in sessions:
        return web.json_response({"error": "session not found"}, status=404)
    s = sessions[sid]
    return web.json_response({
        "session_id":    sid,
        "ip":            s["ip"],
        "started":       s["started"],
        "last_seen":     s["last_seen"],
        "command_count": s["command_count"],
        "cwd":           s["cwd"],
        "alert_count":   s["alert_count"],
        "ttps_seen":     s["ttps_seen"],
        "command_history": [
            h["content"] for h in s["history"] if h["role"] == "user"
        ],
    })


async def handle_session_reset(request: web.Request) -> web.Response:
    sid = request.match_info["session_id"]
    if sid in sessions:
        del sessions[sid]
        return web.json_response({"deleted": sid})
    return web.json_response({"error": "not found"}, status=404)


async def handle_test(request: web.Request) -> web.Response:
    """Quick smoke-test: send a test command and return AI output."""
    test_cmd = request.rel_url.query.get("cmd", "whoami")
    session = get_session("__test__", "127.0.0.1")
    output = await ask_ollama(session, test_cmd)
    ttps = detect_ttps(test_cmd)
    return web.json_response({
        "command": test_cmd,
        "output":  output,
        "ttps":    ttps,
    })


async def handle_stats(request: web.Request) -> web.Response:
    """Token usage statistics for dashboard display."""
    total = token_stats.get("total_prompt", 0) + token_stats.get("total_generated", 0)
    return web.json_response({
        "service":         "honeyai",
        "model":           MODEL,
        "total_tokens":    total,
        "prompt_tokens":   token_stats.get("total_prompt", 0),
        "generated_tokens":token_stats.get("total_generated", 0),
        "total_calls":     token_stats.get("total_calls", 0),
        "active_sessions": len(sessions),
        "alert_sessions":  sum(1 for s in sessions.values() if s["alert_count"] > 0),
        "by_model":        token_stats.get("by_model", {}),
        "started":         token_stats.get("started", ""),
        "last_updated":    token_stats.get("last_updated", ""),
    })


async def handle_openai_completions(request: web.Request) -> web.Response:
    """
    OpenAI-compatible /v1/chat/completions endpoint for Cowrie LLM backend.
    Cowrie sends the full conversation history; we extract the latest command,
    run TTP detection + SENTINEL logging, then call Ollama and return in
    OpenAI response format.
    """
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON"}, status=400)

    messages = body.get("messages", [])
    if not messages:
        return web.json_response({"error": "no messages"}, status=400)

    # Extract attacker IP from the system context Cowrie injects
    # Cowrie formats: "The client IP is '1.2.3.4'" in the context string
    attacker_ip = request.remote or "unknown"
    system_content = ""
    for m in messages:
        if m.get("role") == "system":
            system_content = m.get("content", "")
            break

    import re
    ip_match = re.search(r"client[_ ]ip[^'\"]*['\"]([^'\"]+)['\"]", system_content, re.I)
    if ip_match:
        attacker_ip = ip_match.group(1)

    # Extract the latest user command (last user message)
    command = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            command = m.get("content", "").strip()
            # Cowrie prefixes with "User: " in history
            if command.startswith("User: "):
                command = command[6:]
            break

    if not command:
        # No command yet — return empty (login banner case)
        return web.json_response({
            "id": "chatcmpl-honeyai",
            "object": "chat.completion",
            "model": MODEL,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })

    # Use attacker_ip as session key (Cowrie creates new connection per session)
    session_id = f"cowrie_{attacker_ip}"
    session = get_session(session_id, attacker_ip)
    session["command_count"] += 1

    # TTP detection + alerting
    ttps = detect_ttps(command)
    for t in ttps:
        if t not in session["ttps_seen"]:
            session["ttps_seen"].append(t)
            if t["severity_level"] >= 3:
                session["alert_count"] += 1
                log.warning(
                    f"[!] COWRIE ALERT ip={attacker_ip} "
                    f"TTP={t['technique_id']} ({t['severity'].upper()}): {command[:60]}"
                )

    # Build session history from Cowrie's messages (skip system messages)
    # Cowrie resends full history — rebuild session history from it
    session["history"] = []
    for m in messages:
        role = m.get("role")
        content = m.get("content", "")
        if role == "user":
            cmd_text = content[6:] if content.startswith("User: ") else content
            session["history"].append({"role": "user", "content": cmd_text})
        elif role == "assistant":
            resp_text = content[8:] if content.startswith("System: ") else content
            session["history"].append({"role": "assistant", "content": resp_text})

    output = await ask_ollama(session, command)
    update_cwd(session, command, output)

    # Store latest exchange
    session["history"].append({"role": "user",      "content": command})
    session["history"].append({"role": "assistant",  "content": output})

    asyncio.create_task(post_sentinel_event(session, command, ttps))

    log.info(
        f"[cowrie] {session_id} | {command[:50]!r} "
        f"→ {len(output)}b | ttps={[t['technique_id'] for t in ttps]}"
    )

    return web.json_response({
        "id": "chatcmpl-honeyai",
        "object": "chat.completion",
        "model": MODEL,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": output},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens":     len(command) // 4,
            "completion_tokens": len(output) // 4,
            "total_tokens":      (len(command) + len(output)) // 4,
        },
    })


# ── App setup ──────────────────────────────────────────────────────────────────

def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/health",                        handle_health)
    app.router.add_post("/cmd",                          handle_cmd)
    app.router.add_get("/sessions",                      handle_sessions)
    app.router.add_get("/sessions/{session_id}",         handle_session_detail)
    app.router.add_delete("/sessions/{session_id}",      handle_session_reset)
    app.router.add_get("/test",                          handle_test)
    app.router.add_get("/stats",                          handle_stats)
    # OpenAI-compatible endpoint for Cowrie LLM backend
    app.router.add_post("/v1/chat/completions",          handle_openai_completions)
    return app


if __name__ == "__main__":
    log.info(f"HoneyAI Agent starting on port {PORT}")
    log.info(f"Ollama: {OLLAMA_URL}  model: {MODEL}")
    log.info(f"Victim profile: {PROFILE['hostname']} ({PROFILE['os']})")
    log.info(f"SENTINEL: {SENTINEL_URL}")
    web.run_app(create_app(), host="0.0.0.0", port=PORT, access_log=None)
