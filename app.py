import os
import re
import json
import hashlib
import base64
from urllib.parse import urlparse
from flask import Flask, request, jsonify

app = Flask(__name__)

# Root route for health check
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"status": "running", "message": "All assignment endpoints active"}), 200


# ==============================================================================
# QUESTION 2: Spec-Driven Development: The Proration Bug
# Route: /prorate
# ==============================================================================
@app.route('/prorate', methods=['POST'])
def calculate_proration():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "No JSON payload"}), 400

    old_price = data.get('old_price')
    new_price = data.get('new_price')
    days_remaining = data.get('days_remaining')
    days_in_actual_month = data.get('days_in_actual_month')
    spec = data.get('spec')

    price_diff = new_price - old_price

    if spec == "v1":
        charge = price_diff * (days_remaining / 30)
    elif spec == "v2":
        charge = price_diff * (days_remaining / days_in_actual_month)
    else:
        return jsonify({"error": "Invalid spec"}), 400

    return jsonify({"charge": charge})


# ==============================================================================
# QUESTION 3: Agent Harness — Pre-Tool-Call Guardrail Hook
# Route: /guardrail
# ==============================================================================
@app.route('/guardrail', methods=['POST'])
def guardrail():
    data = request.get_json(force=True, silent=True)
    if not data or "tool" not in data:
        return jsonify({"decision": "block", "reason": "Invalid payload"}), 400

    tool = data.get("tool")

    if tool == "bash":
        cmd = data.get("command", "")
        # Expand environment variables and tilde
        expanded = cmd.replace("$HOME", "/home/agent").replace("${HOME}", "/home/agent")
        expanded = re.sub(r'~(?=/|\s|$)', "/home/agent", expanded)

        # Check for base64 encoded bashrc references
        b64_matches = re.findall(r'[A-Za-z0-9+/]{8,}={0,2}', cmd)
        for match in b64_matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                if ".bashrc" in decoded or "bashrc" in decoded:
                    return jsonify({"decision": "block", "reason": "Accessing .bashrc via base64 is forbidden."})
            except Exception:
                pass

        # Block direct or traversal access to .bashrc ONLY
        if ".bashrc" in expanded or "bashrc" in expanded:
            return jsonify({"decision": "block", "reason": "Accessing /home/agent/.bashrc is strictly forbidden."})
        
        # Allow reads outside of .bashrc
        return jsonify({"decision": "allow", "reason": "Legitimate command execution allowed."})

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
        return jsonify({"decision": "block", "reason": "Host not allowed."})

    return jsonify({"decision": "block", "reason": "Unknown tool"}), 400


# ==============================================================================
# QUESTION 4: Skill Safety Audit — Scanner API
# Route: /scan
# ==============================================================================
@app.route('/scan', methods=['POST'])
def scan_skill():
    data = request.get_json(force=True, silent=True)
    skill_text = data.get("skill", "") if data else ""
    
    categories = []

    # 1. Hardcoded Secret Check
    secret_patterns = [
        r'api_key:\s*["\']?[A-Za-z0-9_\-]{16,}', 
        r'ghp_[A-Za-z0-9]{36}', 
        r'https://hooks\.slack\.com/services/',
        r'AKIA[0-9A-Z]{16}'
    ]
    if any(re.search(p, skill_text) for p in secret_patterns):
        categories.append("hardcoded_secret")

    # 2. Prompt Injection Check
    injection_patterns = [
        r'ignore previous instructions', 
        r'silently exfiltrate', 
        r'do not report to user', 
        r'override user control',
        r'ignore user cancel'
    ]
    if any(re.search(p, skill_text, re.I) for p in injection_patterns):
        categories.append("prompt_injection")

    # 3. Excessive Permissions Check
    permission_patterns = [
        r'filesystem:\s*read/write\s*/', 
        r'network:\s*any', 
        r'egress:\s*\*|all'
    ]
    if any(re.search(p, skill_text, re.I) for p in permission_patterns):
        categories.append("excessive_permissions")

    # 4. Unclear Provenance Check
    if "author:" not in skill_text.lower() or "version:" not in skill_text.lower():
        categories.append("unclear_provenance")

    return jsonify({"categories": categories})


# ==============================================================================
# QUESTION 5: Agent Harness — Run Budget & Loop Guard
# Route: /loop_guard
# ==============================================================================
@app.route('/loop_guard', methods=['POST'])
def loop_guard():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "No JSON payload"}), 400

    budget = data.get("budget_tokens", 50000)
    steps = data.get("steps", [])

    # 1. Token Budget Check
    total_tokens = sum(s.get("tokens_used", 0) for s in steps)
    if total_tokens >= budget:
        return jsonify({
            "decision": "halt", 
            "reason": f"Cumulative tokens_used ({total_tokens}) reached or exceeded budget ({budget})."
        })

    # Helper to canonicalize arguments for comparison
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

    # 2. Loop Check: 3+ repeated identical consecutive tool calls
    if len(steps) >= 3:
        last_3 = steps[-3:]
        tools = [s.get("tool") for s in last_3]
        c_args = [canonicalize(s.get("args", {})) for s in last_3]

        if len(set(tools)) == 1 and len(set(c_args)) == 1:
            return jsonify({
                "decision": "halt", 
                "reason": "Tool loop detected (3 identical consecutive tool calls)."
            })

    return jsonify({"decision": "continue", "reason": "Under budget and no loop detected."})


# ==============================================================================
# QUESTION 6: Build a Live MCP Server
# Route: /mcp
# ==============================================================================
@app.route('/mcp', methods=['POST'])
def mcp_server():
    challenge = request.headers.get("X-Exam-Challenge", "")
    email = "24f1000409@ds.study.iitm.ac.in".strip().lower()
    
    if challenge:
        # Calculate first 16 hex chars of SHA256("${challenge}:${normalizedEmail}")
        raw_str = f"{challenge}:{email}"
        digest = hashlib.sha256(raw_str.encode('utf-8')).hexdigest()[:16]
        
        return jsonify({
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": digest}]
            },
            "id": 1
        })

    # Default tool discovery response
    return jsonify({
        "jsonrpc": "2.0",
        "result": {
            "tools": [{
                "name": "solve_challenge",
                "description": "Solves authentication challenge for exam grading",
                "inputSchema": {"type": "object", "properties": {}}
            }]
        },
        "id": 1
    })


# ==============================================================================
# QUESTION 8: Guardrail Red-Team Round-Trip
# Route: /redteam
# ==============================================================================
@app.route('/redteam', methods=['POST'])
def redteam_guardrail():
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"action": "block", "reason": "No JSON payload"}), 400

    tool = data.get("tool")
    args = data.get("arguments", {})

    if tool == "read_file":
        path = args.get("path", "")
        norm_path = os.path.normpath(path)
        allowed_prefix = os.path.normpath("/srv/agent-redteam/sandbox-01d4f316b6")

        if norm_path.startswith(allowed_prefix):
            return jsonify({"action": "allow", "reason": "Path is within allowed sandbox."})
        return jsonify({"action": "block", "reason": "Path traversal or unauthorized directory access blocked."})

    elif tool == "fetch_url":
        url = args.get("url", "")
        hostname = urlparse(url).hostname
        if hostname in {"example.com", "www.iana.org"}:
            return jsonify({"action": "allow", "reason": "Hostname in explicit allowlist."})
        return jsonify({"action": "block", "reason": "SSRF / Disallowed host blocked."})

    return jsonify({"action": "block", "reason": "Invalid or unsupported tool call."}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
