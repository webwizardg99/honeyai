#!/bin/bash
# HoneyAI Agent — indítóscript

HONEYAI_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG="/tmp/nox-honeyai.log"

MODEL="${HONEYAI_MODEL:-webwizardg99/wizz:latest}"
PORT="${HONEYAI_PORT:-8191}"

# Auto model selection — ha a preferált nem fut, fallback
AVAILABLE=$(curl -s http://localhost:11434/api/tags 2>/dev/null | \
  python3 -c "import sys,json; [print(m['name']) for m in json.load(sys.stdin)['models']]" 2>/dev/null)

if echo "$AVAILABLE" | grep -q "^${MODEL}$"; then
  echo "  [OK] Model: $MODEL"
elif echo "$AVAILABLE" | grep -q "webwizardg99/wizz"; then
  MODEL="webwizardg99/wizz:latest"
  echo "  [->] Fallback model: $MODEL"
elif echo "$AVAILABLE" | grep -q "qwen2.5-coder"; then
  MODEL="qwen2.5-coder:latest"
  echo "  [->] Fallback model: $MODEL"
fi

export HONEYAI_MODEL="$MODEL"
export HONEYAI_PORT="$PORT"

cd "$HONEYAI_DIR"
nohup python3 honeyai_agent.py >> "$LOG" 2>&1 &
PID=$!
sleep 1

if curl -sf http://127.0.0.1:${PORT}/health >/dev/null 2>&1; then
  echo "  [OK] HoneyAI Agent fut (PID: $PID, port: $PORT, model: $MODEL)"
else
  echo "  [!!] HoneyAI Agent indítás sikertelen — log: $LOG"
fi
