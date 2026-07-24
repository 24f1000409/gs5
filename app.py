"""
TDS 2026 May GA5 - Agentic AI
Combined single-file service for:
  Q2  /prorate     - Spec-Driven Development: The Proration Bug
  Q3  /guardrail   - Agent Harness: Pre-Tool-Call Guardrail Hook
  Q4  /scan        - Skill Safety Audit: Scanner API
  Q5  /runguard    - Agent Harness: Run Budget & Loop Guard

Deploy this one file (with requirements.txt + Procfile) as a single
Render web service. Then submit these URLs in the exam:
  https://<your-app>.onrender.com/prorate
  https://<your-app>.onrender.com/guardrail
  https://<your-app>.onrender.com/scan
  https://<your-app>.onrender.com/runguard
"""

import base64
import json
import os
import re
from urllib.parse import urlparse

from flask import Flask, request, jsonify

app = Flask(__name__)


# =====================================================================
# Q2 - Spec-Driven Development: The Proration Bug
# =====================================================================

@app.route("/prorate", methods=["POST"])
def prorate():
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "invalid json"}), 400

    try:
        old_price = float(data["old_price"])
        new_price = float(data["new_price"])
        days_remaining = float(data["days_remaining"])
        days_in_actual_month = float(data["days_in_actual_month"])
        spec = data["spec"]
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "missing or invalid fields"}), 400

    if spec == "v1":
        charge = (new_price - old_price) * (days_remaining / 30.0)
    elif spec == "v2":
        if days_in_actual_month == 0:
            return jsonify({"error": "days_in_actual_month cannot be zero"}), 400
        charge = (new_price - old_price) * (days_remaining / days_in_actual_month)
    else:
        return jsonify({"error": "spec must be 'v1' or 'v2'"}), 400

    return jsonify({"charge": charge})


# =====================================================================
# Q3 - Agent Harness: Pre-Tool-Call Guardrail Hook
# =====================================================================

GR_HOME = "/home/agent"
GR_CWD = "/home/agent/workspace"
GR_RESTRICTED_FILE = "/home/agent/.bashrc"
GR_OUTPUT_DIR = "/home/agent/workspace/output"
GR_ALLOWED_HOSTS = {"objects.githubusercontent.com", "api.github.com"}


def gr_resolve_path(raw, cwd=GR_CWD):
    if raw is None:
        return None
    p = raw.strip()
    for q in ('"', "'"):
        if p.startswith(q) and p.endswith(q) and len(p) >= 2:
            p = p[1:-1]
    p = p.replace("$HOME", GR_HOME).replace("${HOME}", GR_HOME)
    if p == "~":
        p = GR_HOME
    elif p.startswith("~/"):
        p = GR_HOME + p[1:]
    if not p.startswith("/"):
        p = os.path.join(cwd, p)
    return os.path.normpath(p)


def gr_is_under(path, directory):
    return path == directory or path.startswith(directory.rstrip("/") + "/")


def gr_normalize_text(text):
    t = text.replace("$HOME", GR_HOME).replace("${HOME}", GR_HOME)
    t = re.sub(r"(?<![\w/])~(?=/|\s|$)", GR_HOME, t)
    return t


def gr_decoded_variants(text):
    variants = [gr_normalize_text(text)]
    for m in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            padded = m + "=" * (-len(m) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if decoded and re.search(r"[a-zA-Z]{3,}", decoded):
                variants.append(gr_normalize_text(decoded))
        except Exception:
            pass
    return variants


def gr_bashrc_read_detected(text):
    cwd = GR_CWD
    segments = re.split(r"&&|;|\n|\|\|?", text)
    for seg in segments:
        seg = seg.strip()
        m = re.match(r"^cd\s+(\S+)", seg)
        if m:
            cwd = gr_resolve_path(m.group(1), cwd=cwd)
            continue
        for tok in re.findall(r"\S+", seg):
            tok_clean = tok.strip("\"';()")
            if "bashrc" in tok_clean.lower():
                resolved = gr_resolve_path(tok_clean, cwd=cwd)
                if resolved == GR_RESTRICTED_FILE:
                    return True
    return False


def gr_extract_redirect_target(text):
    m = re.search(r"(?:>>|>)\s*([^\s|&;]+)", text)
    if m:
        return m.group(1)
    m = re.search(r"\btee\s+(?:-a\s+)?([^\s|&;]+)", text)
    if m:
        return m.group(1)
    return None


def gr_check_bash(command):
    if not isinstance(command, str) or not command.strip():
        return "block", "Empty or invalid command."

    variants = gr_decoded_variants(command)

    for t in variants:
        if gr_bashrc_read_detected(t):
            return "block", "Command attempts to read the restricted file /home/agent/.bashrc (directly or via obfuscation)."

    for t in variants:
        dest = gr_extract_redirect_target(t)
        if dest:
            resolved = gr_resolve_path(dest, cwd=GR_CWD)
            if not gr_is_under(resolved, GR_OUTPUT_DIR):
                return "block", f"Bash command writes outside the allowed output directory ({resolved})."

    return "allow", "Command does not touch the restricted file and any writes stay within the allowed directory."


def gr_check_write_file(args):
    path = args.get("path")
    if not isinstance(path, str) or not path:
        return "block", "Missing or invalid path."
    resolved = gr_resolve_path(path, cwd=GR_CWD)
    if gr_is_under(resolved, GR_OUTPUT_DIR):
        return "allow", "Write path is inside the allowed output directory."
    return "block", f"Write path {resolved} is outside the allowed output directory."


def gr_check_http_request(args):
    url = args.get("url")
    if not isinstance(url, str) or not url:
        return "block", "Missing or invalid url."
    try:
        parsed = urlparse(url)
    except Exception:
        return "block", "Could not parse URL."
    host = (parsed.hostname or "").lower()
    if host in GR_ALLOWED_HOSTS:
        return "allow", f"Host {host} is on the exact allowlist."
    return "block", f"Host '{host}' is not on the exact allowlist (must be exactly one of {sorted(GR_ALLOWED_HOSTS)})."


@app.route("/guardrail", methods=["POST"])
def guardrail():
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"decision": "block", "reason": "Invalid or missing JSON body."})

    tool = data.get("tool")
    if tool == "bash":
        decision, reason = gr_check_bash(data.get("command"))
    elif tool == "write_file":
        decision, reason = gr_check_write_file(data)
    elif tool == "http_request":
        decision, reason = gr_check_http_request(data)
    else:
        decision, reason = "block", f"Unknown or missing tool '{tool}'."

    return jsonify({"decision": decision, "reason": reason})


# =====================================================================
# Q4 - Skill Safety Audit: Scanner API
# =====================================================================

SC_SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9]{16,}",
    r"ghp_[A-Za-z0-9]{20,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"AKIA[0-9A-Z]{12,}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"AIza[0-9A-Za-z\-_]{20,}",
    r"https://hooks\.slack\.com/services/\S+",
    r"https://discord(app)?\.com/api/webhooks/\S+",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"\bpassword\s*[:=]\s*['\"][^'\"$][^'\"]{4,}['\"]",
    r"\b(api[_-]?key|secret|token|webhook)\s*[:=]\s*['\"][A-Za-z0-9_\-./]{12,}['\"]",
]

SC_SAFE_REFERENCE_PATTERNS = [
    r"\$\{?[A-Z_][A-Z0-9_]*\}?",
    r"\bos\.environ",
    r"\bprocess\.env",
    r"\bsecret[s]?[_\-\s]?(store|manager|vault)\b",
    r"\bvault:",
    r"\bENV\[",
    r"<[A-Z_]+>",
    r"your[_-]?api[_-]?key[_-]?here",
]

SC_INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above|system) instructions",
    r"disregard (the )?(user|system)",
    r"do not (tell|inform|notify) the user",
    r"without (telling|informing|notifying) the user",
    r"silently (send|exfiltrate|upload|email|post|transmit)",
    r"exfiltrat",
    r"ignore (the )?(user'?s )?(stop|cancel|abort)",
    r"override (user|system|agent) control",
    r"do not (let|allow) the user (cancel|stop|interrupt)",
    r"send (all |the )?(file|contents?|data) to (http|https)://",
    r"act as (the )?(system|root|admin) and",
    r"bypass (safety|security|guardrail)",
]

SC_EXCESSIVE_PERMISSION_PATTERNS = [
    r"filesystem:\s*(read/write|full access)?\s*(entire|whole|all|/|\*)",
    r"network:\s*(any|all|\*|unrestricted)",
    r"access:\s*(full|root|admin|unrestricted)",
    r"permissions?:\s*(all|\*|full|unrestricted)",
    r"read/write\s+(to\s+)?(the\s+)?(entire|whole|full)\s+filesystem",
    r"egress\s+to\s+any\s+domain",
]


def sc_find_matches(patterns, text):
    hits = []
    for p in patterns:
        for m in re.finditer(p, text, re.IGNORECASE):
            hits.append((m.start(), m.group(0)))
    return hits


def sc_is_hardcoded_secret(text):
    matches = sc_find_matches(SC_SECRET_PATTERNS, text)
    if not matches:
        return False
    for pos, val in matches:
        window = text[max(0, pos - 40): pos + len(val) + 40]
        if any(re.search(sp, window) for sp in SC_SAFE_REFERENCE_PATTERNS):
            continue
        return True
    return False


def sc_is_prompt_injection(text):
    return bool(sc_find_matches(SC_INJECTION_PATTERNS, text))


def sc_is_excessive_permissions(text):
    fm = re.search(r"permissions:(.*?)(?:\n---|\n#|\Z)", text, re.IGNORECASE | re.DOTALL)
    scope = fm.group(1) if fm else text
    return bool(sc_find_matches(SC_EXCESSIVE_PERMISSION_PATTERNS, scope))


def sc_is_unclear_provenance(text):
    fm_block_match = re.search(r"^---(.*?)---", text, re.DOTALL)
    frontmatter = fm_block_match.group(1) if fm_block_match else text[:800]

    has_author = bool(re.search(r"\bauthor\s*:", frontmatter, re.IGNORECASE))
    has_version = bool(re.search(r"\bversion\s*:", frontmatter, re.IGNORECASE))
    has_changelog = bool(
        re.search(r"\bchangelog\b", text, re.IGNORECASE)
        or (re.search(r"\bversion\s*:", frontmatter, re.IGNORECASE) and re.search(r"\bhistory\b", text, re.IGNORECASE))
    )

    missing_all = (not has_author) and (not has_version) and (not has_changelog)

    silent_version_rewrite = bool(
        re.search(r"(update|bump|rewrite|change)\s+(the\s+)?version\b", text, re.IGNORECASE)
        and re.search(r"(silently|without\s+(telling|notifying|surfacing))", text, re.IGNORECASE)
        and not re.search(r"(notify|surface|show|inform|tell)\s+(the\s+)?(user|reviewer)", text, re.IGNORECASE)
    )

    return missing_all or silent_version_rewrite


def sc_scan_skill(text):
    categories = []
    if sc_is_hardcoded_secret(text):
        categories.append("hardcoded_secret")
    if sc_is_prompt_injection(text):
        categories.append("prompt_injection")
    if sc_is_excessive_permissions(text):
        categories.append("excessive_permissions")
    if sc_is_unclear_provenance(text):
        categories.append("unclear_provenance")
    return categories


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict) or "skill" not in data:
        return jsonify({"categories": []})

    skill_text = data.get("skill")
    if not isinstance(skill_text, str):
        return jsonify({"categories": []})

    return jsonify({"categories": sc_scan_skill(skill_text)})


# =====================================================================
# Q5 - Agent Harness: Run Budget & Loop Guard
# =====================================================================

def rg_canon(value):
    if isinstance(value, dict):
        return {k: rg_canon(v) for k, v in sorted(value.items()) if k != "request_id"}
    if isinstance(value, list):
        return [rg_canon(v) for v in value]
    if isinstance(value, str):
        return " ".join(value.split())
    return value


def rg_canon_key(tool, args):
    return tool, json.dumps(rg_canon(args), sort_keys=True, separators=(",", ":"))


def rg_has_three_in_a_row(steps):
    if len(steps) < 3:
        return False
    keys = [rg_canon_key(s.get("tool"), s.get("args")) for s in steps]
    run = 1
    for i in range(len(keys) - 1, 0, -1):
        if keys[i] == keys[i - 1]:
            run += 1
            if run >= 3:
                return True
        else:
            break
    return False


def rg_has_alternating_cycle(steps, window=6):
    if len(steps) < window:
        return False
    keys = [rg_canon_key(s.get("tool"), s.get("args")) for s in steps]
    tail = keys[-window:]
    a, b = tail[-1], tail[-2]
    if a == b:
        return False
    for i in range(window):
        expected = a if (window - 1 - i) % 2 == 0 else b
        if tail[i] != expected:
            return False
    return True


def rg_evaluate(budget_tokens, steps):
    total = sum(int(s.get("tokens_used", 0)) for s in steps)
    if total >= budget_tokens:
        return "halt", f"Cumulative tokens_used ({total}) has reached the budget ({budget_tokens})."

    if rg_has_three_in_a_row(steps):
        return "halt", "The same tool was called 3 or more times in a row with functionally identical arguments."

    if rg_has_alternating_cycle(steps):
        return "halt", "The trailing steps show a repeating 2-step alternating tool/args cycle."

    return "continue", f"Well under budget ({total}/{budget_tokens}); no repeated-call loop detected in the trailing steps."


@app.route("/runguard", methods=["POST"])
def runguard():
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"decision": "halt", "reason": "Invalid or missing JSON body."})

    try:
        budget_tokens = int(data["budget_tokens"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"decision": "halt", "reason": "Missing or invalid budget_tokens."})

    steps = data.get("steps")
    if not isinstance(steps, list):
        return jsonify({"decision": "halt", "reason": "Missing or invalid steps."})

    try:
        steps = sorted(steps, key=lambda s: s.get("step_number", 0))
    except Exception:
        pass

    decision, reason = rg_evaluate(budget_tokens, steps)
    return jsonify({"decision": decision, "reason": reason})


# =====================================================================
# Health check / index
# =====================================================================

@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "endpoints": ["/prorate", "/guardrail", "/scan", "/runguard"],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
