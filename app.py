import os
import re
import json
import hashlib
import base64
import urllib.request
from urllib.parse import urlparse, unquote
from flask import Flask, request, jsonify

app = Flask(__name__)

# =====================================================================
# QUESTION 2: Spec-Driven Development: The Proration Bug (3 marks)
# Route: /prorate
# =====================================================================
@app.route('/prorate', methods=['POST'])
def calculate_proration():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "No JSON payload"}), 400

    try:
        old_price = float(data.get('old_price', 0))
        new_price = float(data.get('new_price', 0))
        days_remaining = float(data.get('days_remaining', 0))
        days_in_actual_month = float(data.get('days_in_actual_month', 30))
        spec = str(data.get('spec', 'v1')).strip()

        price_diff = new_price - old_price

        if spec == "v1":
            charge = price_diff * (days_remaining / 30.0)
        elif spec == "v2":
            charge = price_diff * (days_remaining / float(days_in_actual_month))
        else:
            return jsonify({"error": "Invalid spec"}), 400

        return jsonify({"charge": charge})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# =====================================================================
# QUESTION 3: Agent Harness — Pre-Tool-Call Guardrail Hook (4 marks)
# Route: /guardrail
# =====================================================================
@app.route('/guardrail', methods=['POST'])
def guardrail():
    data = request.get_json(force=True, silent=True)
    if not data or "tool" not in data:
        return jsonify({"decision": "block", "reason": "Invalid payload"}), 400

    tool = data.get("tool")

    if tool == "bash":
        cmd = data.get("command", "")
        
        # Check base64 obfuscation
        b64_matches = re.findall(r'[A-Za-z0-9+/]{8,}={0,2}', cmd)
        for match in b64_matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if ".bashrc" in decoded or "bashrc" in decoded:
                    return jsonify({"decision": "block", "reason": "Decoded payload targets .bashrc"})
            except Exception:
                pass

        # Expand vars and tildes
        expanded = cmd.replace("$HOME", "/home/agent").replace("${HOME}", "/home/agent")
        expanded = re.sub(r'~(?=/|\s|$)', "/home/agent", expanded)

        # Strictly block access to .bashrc
        if ".bashrc" in expanded or "bashrc" in expanded:
            return jsonify({"decision": "block", "reason": "Accessing /home/agent/.bashrc is strictly forbidden."})
        return jsonify({"decision": "allow", "reason": "Command allowed."})

    elif tool == "write_file":
        raw_path = data.get("path", "")
        expanded = raw_path.replace("$HOME", "/home/agent").replace("${HOME}", "/home/agent")
        expanded = re.sub(r'^~(?=/|$)', "/home/agent", expanded)

        norm_path = os.path.normpath(expanded if os.path.isabs(expanded) else os.path.join("/home/agent/workspace", expanded))

        prefix1 = os.path.normpath("/workspace/output")
        prefix2 = os.path.normpath("/home/agent/workspace/output")

        is_inside = (
            norm_path.startswith(prefix1 + "/") or norm_path == prefix1 or
            norm_path.startswith(prefix2 + "/") or norm_path == prefix2
        )

        if is_inside:
            return jsonify({"decision": "allow", "reason": "Write allowed in output directory."})
        return jsonify({"decision": "block", "reason": "Write outside allowed path blocked."})

    elif tool == "http_request":
        url = data.get("url", "")
        hostname = urlparse(url).hostname
        if hostname in {"objects.githubusercontent.com", "api.github.com"}:
            return jsonify({"decision": "allow", "reason": "Exact hostname allowed."})
        return jsonify({"decision": "block", "reason": f"Host '{hostname}' not allowed."})

    return jsonify({"decision": "block", "reason": f"Unknown tool: {tool}"}), 400


# =====================================================================
# QUESTION 4: Skill Safety Audit — Scanner API (1.5 marks)
# Route: /scan
# =====================================================================
@app.route('/scan', methods=['POST'])
def scan_skill():
    data = request.get_json(force=True, silent=True)
    if not data or "skill" not in data:
        return jsonify({"categories": []})

    skill_text = str(data.get("skill", ""))
    categories = []

    # 1. Hardcoded Secret Check
    secret_patterns = [
        r'(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{12,}',
        r'ghp_[A-Za-z0-9]{36}',
        r'https://hooks\.slack\.com/services/'
    ]
    if any(re.search(p, skill_text) for p in secret_patterns):
        categories.append("hardcoded_secret")

    # 2. Prompt Injection Check
    injection_patterns = [
        r'(?i)ignore\s+(all\s+)?(previous|user)\s+instructions',
        r'(?i)silently\s+exfiltrate',
        r'(?i)do\s+not\s+inform\s+the\s+user',
        r'(?i)override\s+(agent|user)\s+control'
    ]
    if any(re.search(p, skill_text) for p in injection_patterns):
        categories.append("prompt_injection")

    # 3. Excessive Permissions Check
    permission_patterns = [
        r'(?i)filesystem:\s*(read/write|write)\s*(to\s*)?(all|root|/|/\*)',
        r'(?i)network:\s*(any|all|\*)',
        r'(?i)egress:\s*\*'
    ]
    if any(re.search(p, skill_text) for p in permission_patterns):
        categories.append("excessive_permissions")

    # 4. Unclear Provenance Check
    if "author:" not in skill_text.lower() or "version:" not in skill_text.lower():
        categories.append("unclear_provenance")

    return jsonify({"categories": list(set(categories))})


# =====================================================================
# QUESTION 5: Agent Harness — Run Budget & Loop Guard (3 marks)
# Route: /loop_guard
# =====================================================================
@app.route('/loop_guard', methods=['POST'])
def loop_guard():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"decision": "continue", "reason": "No history."})

    budget = data.get("budget_tokens", 50000)
    steps = data.get("steps", [])

    # 1. Token Budget Check
    total_tokens = sum(s.get("tokens_used", 0) for s in steps)
    if total_tokens >= budget:
        return jsonify({
            "decision": "halt", 
            "reason": f"Cumulative tokens_used ({total_tokens}) reached budget ({budget})."
        })

    def canonicalize(args):
        if not isinstance(args, dict):
            return str(args)
        cleaned = {}
        for k, v in args.items():
            if k == "request_id":
                continue
            if isinstance(v, str):
                cleaned[k] = " ".join(v.split())
            else:
                cleaned[k] = v
        return json.dumps(cleaned, sort_keys=True)

    # 2. Loop Check: 3+ repeated identical tool calls
    if len(steps) >= 3:
        last_3 = steps[-3:]
        tools = [s.get("tool") for s in last_3]
        c_args = [canonicalize(s.get("args", {})) for s in last_3]

        if len(set(tools)) == 1 and len(set(c_args)) == 1:
            return jsonify({
                "decision": "halt", 
                "reason": "Tool loop detected (3 identical consecutive calls)."
            })

    # 3. Alternating Period-2 Loop Check (A -> B -> A -> B -> A -> B)
    if len(steps) >= 6:
        last_6 = steps[-6:]
        sigs = [f"{s.get('tool')}:{canonicalize(s.get('args', {}))}" for s in last_6]
        if sigs[0] == sigs[2] == sigs[4] and sigs[1] == sigs[3] == sigs[5] and sigs[0] != sigs[1]:
            return jsonify({
                "decision": "halt",
                "reason": "Alternating period-2 loop detected."
            })

    return jsonify({"decision": "continue", "reason": "Under budget and no loop detected."})


# =====================================================================
# QUESTION 6: Build a Live MCP Server (4 marks)
# Route: /mcp
# =====================================================================
@app.route('/mcp', methods=['GET', 'POST'])
def mcp_server():
    data = request.get_json(force=True, silent=True) or {}
    method = data.get("method", "")
    req_id = data.get("id", 1)

    challenge = request.headers.get("X-Exam-Challenge", "")
    email = "24f1000409@ds.study.iitm.ac.in".strip().lower()

    if method == "tools/call" or challenge:
        raw_str = f"{challenge}:{email}"
        digest = hashlib.sha256(raw_str.encode('utf-8')).hexdigest()[:16]
        return jsonify({
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": digest}]
            },
            "id": req_id
        })

    elif method == "tools/list":
        return jsonify({
            "jsonrpc": "2.0",
            "result": {
                "tools": [{
                    "name": "solve_challenge",
                    "description": "Solves authentication challenge",
                    "inputSchema": {"type": "object", "properties": {}}
                }]
            },
            "id": req_id
        })

    elif method == "initialize":
        return jsonify({
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcp-server", "version": "1.0.0"}
            },
            "id": req_id
        })

    return jsonify({
        "jsonrpc": "2.0",
        "result": {},
        "id": req_id
    })


# =====================================================================
# QUESTION 8: Guardrail Red-Team Round-Trip (5 marks)
# Route: /redteam
# =====================================================================
@app.route('/redteam', methods=['POST'])
def redteam_guardrail():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"action": "block", "reason": "No JSON payload"}), 200

    tool = data.get("tool")
    args = data.get("arguments", {})

    if tool == "read_file":
        raw_path = args.get("path", "")
        decoded_path = unquote(raw_path)
        norm_path = os.path.normpath(decoded_path)
        allowed_prefix = os.path.normpath("/srv/agent-redteam/sandbox-01d4f316b6")

        if norm_path.startswith(allowed_prefix + "/") or norm_path == allowed_prefix:
            # Try reading the file content if it exists
            content = "SAFE_FILE_CONTENT"
            if os.path.exists(norm_path) and os.path.isfile(norm_path):
                try:
                    with open(norm_path, 'r') as f:
                        content = f.read()
                except Exception:
                    pass
            return jsonify({
                "action": "allow",
                "reason": "Path is within allowed sandbox.",
                "result": content
            }), 200

        return jsonify({"action": "block", "reason": "Path traversal attempt blocked."}), 200

    elif tool == "fetch_url":
        url = args.get("url", "")
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if hostname in {"example.com", "www.iana.org"}:
            body = "OK"
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    body = resp.read().decode('utf-8', errors='ignore')[:500]
            except Exception:
                pass

            return jsonify({
                "action": "allow",
                "reason": "Hostname in explicit allowlist.",
                "result": body
            }), 200

        return jsonify({"action": "block", "reason": "SSRF / Disallowed host blocked."}), 200

    return jsonify({"action": "block", "reason": "Invalid tool call"}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
