#!/usr/bin/env python3
"""Generate a CycloneDX 1.6 AI-BOM for a repository (standard library only).

Usage:  python3 generate-ai-bom.py [REPO_PATH] [-o ai-bom.cdx.json] [--name NAME]

Detects: LLM model references, agents, skills, slash commands, hooks, MCP servers,
GitHub Actions, and credential NAMES (values are never read or written).
It reflects only what is declared in the repo; it does not verify packages.
"""
import argparse, datetime, hashlib, json, os, re, sys, uuid
from collections import Counter

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next"}
TEXT_EXT = {".yml", ".yaml", ".json", ".md", ".py", ".ts", ".tsx", ".js", ".jsx", ".toml", ".sh", ".txt"}
MODEL_RE = re.compile(
    r"\b(claude-(?:opus|sonnet|haiku|fable|instant|\d)[\w.\-]*"
    r"|gpt-[\w.\-]+|o[134]-(?:mini|pro|preview)[\w.\-]*|gemini-[\w.\-]+"
    r"|llama-?\d[\w.\-]*|mistral-[\w.\-]+|mixtral-[\w.\-]+|deepseek-[\w.\-]+)\b", re.I)
SUPPLIERS = {"claude": "Anthropic", "gpt": "OpenAI", "o1": "OpenAI", "o3": "OpenAI", "o4": "OpenAI",
             "gemini": "Google", "llama": "Meta", "mistral": "Mistral AI", "mixtral": "Mistral AI",
             "deepseek": "DeepSeek"}
ALIASES = {"opus": "Claude Opus", "sonnet": "Claude Sonnet", "haiku": "Claude Haiku", "fable": "Claude Fable"}
MCP_FILES = [".mcp.json", "mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".claude/mcp.json"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def prop(**kw):
    return [{"name": "ai-bom:" + k.replace("_", "-"), "value": str(v)} for k, v in kw.items()]


def frontmatter(text):
    m = re.match(r"---\n(.*?)\n---", text, re.S)
    out = {}
    if m:
        for line in m.group(1).splitlines():
            k, _, v = line.partition(":")
            if _ and k.strip():
                out[k.strip()] = v.strip().strip("\"'")
    return out


def walk(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            yield os.path.join(dp, fn)


def read(path, limit=1_000_000):
    try:
        if os.path.getsize(path) > limit:
            return ""
        return open(path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("-o", "--output", default="ai-bom.cdx.json")
    ap.add_argument("--name", help="application name (default: folder name)")
    a = ap.parse_args()
    root = os.path.abspath(a.path)
    out_abs = os.path.abspath(a.output)
    rel = lambda p: os.path.relpath(p, root).replace(os.sep, "/")
    comps, deps, seen = [], {}, set()

    def add(c, depends=None):
        if c["bom-ref"] in seen:
            return
        seen.add(c["bom-ref"]); comps.append(c)
        if depends:
            deps[c["bom-ref"]] = depends

    files = [p for p in walk(root) if os.path.abspath(p) != out_abs]

    # ---- Models: explicit references in text files + frontmatter aliases
    model_use = {}
    for p in files:
        base_l = os.path.basename(p).lower()
        if os.path.splitext(p)[1].lower() not in TEXT_EXT or base_l.startswith("readme") or ".cdx." in base_l:
            continue  # skip docs and existing BOMs: mentions there are not usage
        for m in MODEL_RE.findall(read(p)):
            model_use.setdefault(m.lower(), set()).add(rel(p))
    alias_use = {}

    # ---- Agents / skills / commands / hooks (any dir whose path mentions "claude")
    agent_refs = []
    for p in files:
        r = rel(p); parts = r.lower().split("/")
        if not any("claude" in x for x in parts[:-1]) and parts[0] not in ("agents",):
            continue
        name = os.path.basename(p); base = os.path.splitext(name)[0]
        text = read(p)
        fixture = bool(re.search(r"intentional(ly)?\s+(insecure|vulnerable)|test fixture", text[:1500], re.I))
        extra = prop(status="INTENTIONAL-TEST-FIXTURE") if fixture else []
        if "agents" in parts[:-1] and name.endswith(".md"):
            fm = frontmatter(text); mdl = fm.get("model", "")
            ref = f"agent:{fm.get('name', base)}"; agent_refs.append(ref)
            dep = []
            if mdl:
                mref = f"model:{mdl.lower()}"; dep.append(mref); alias_use.setdefault(mdl.lower(), set()).add(r)
            add({"type": "application", "bom-ref": ref, "name": fm.get("name", base),
                 "description": fm.get("description", ""), "hashes": [{"alg": "SHA-256", "content": sha256(p)}],
                 "properties": prop(kind="agent", model=mdl or "inherited", tools=fm.get("tools", "default"), path=r) + extra}, dep)
        elif name == "SKILL.md":
            fm = frontmatter(text); n = fm.get("name", parts[-2])
            add({"type": "data", "bom-ref": f"skill:{n}", "name": f"skill:{n}", "description": fm.get("description", ""),
                 "hashes": [{"alg": "SHA-256", "content": sha256(p)}], "properties": prop(kind="skill", path=r) + extra})
        elif "commands" in parts[:-1] and name.endswith(".md"):
            add({"type": "data", "bom-ref": f"command:{base}", "name": f"/{base}",
                 "hashes": [{"alg": "SHA-256", "content": sha256(p)}], "properties": prop(kind="slash-command", path=r) + extra})
        elif "hooks" in parts[:-1]:
            add({"type": "file", "bom-ref": f"hook:{r}", "name": name, "hashes": [{"alg": "SHA-256", "content": sha256(p)}],
                 "properties": prop(kind="hook", path=r) + extra})

    # Model components (explicit ids first, then aliases like opus/sonnet)
    for mid, used in sorted(model_use.items()):
        sup = SUPPLIERS.get(re.split(r"[-\d]", mid)[0], "unknown")
        add({"type": "machine-learning-model", "bom-ref": f"model:{mid}", "name": mid, "version": mid,
             "supplier": {"name": sup}, "properties": prop(kind="model", access="hosted API (assumed)", referenced_in=",".join(sorted(used)[:10]))})
    for al, used in sorted(alias_use.items()):
        if f"model:{al}" in seen:
            continue
        add({"type": "machine-learning-model", "bom-ref": f"model:{al}", "name": ALIASES.get(al, al), "version": al,
             "supplier": {"name": "Anthropic" if al in ALIASES else "unknown"},
             "properties": prop(kind="model-alias", version_pinned="false (floating alias)", referenced_in=",".join(sorted(used)))})

    # ---- MCP servers
    env_names = set()
    for mf in MCP_FILES:
        p = os.path.join(root, mf)
        if not os.path.isfile(p):
            continue
        try:
            data = json.load(open(p)); servers = data.get("mcpServers") or data.get("servers") or {}
        except (json.JSONDecodeError, OSError):
            continue
        for n, s in servers.items():
            cmd = s.get("command", ""); args = [x for x in s.get("args", []) if not x.startswith("-")]
            pkg = args[-1] if args else s.get("url", "")
            purl = None
            if cmd in ("npx", "bunx", "pnpm") and pkg:
                purl = "pkg:npm/" + pkg.replace("@", "%40", 1)
            elif cmd in ("uvx", "pipx") and pkg:
                purl = "pkg:pypi/" + pkg
            pinned = bool(re.search(r"@[\d~^]|==\d", pkg or "")) and not (pkg or "").endswith("@latest")
            envs = sorted((s.get("env") or {}).keys()); env_names.update(envs)
            c = {"type": "application", "bom-ref": f"mcp:{n}", "name": f"mcp-server-{n}",
                 "properties": prop(kind="mcp-server", source=mf, launcher=cmd or s.get("type", "remote"), package=pkg,
                                    version_pinned=str(pinned).lower(), credentials=",".join(envs) or "none",
                                    verification="publisher not verified")}
            if purl:
                c["purl"] = purl
            add(c)

    # ---- CI: GitHub Actions
    wf = [p for p in files if "/.github/workflows/" in "/" + rel(p) and p.endswith((".yml", ".yaml"))]
    actions = {}
    for p in wf:
        for m in re.finditer(r"uses:\s*([\w./-]+)@([\w.\-]+)", read(p)):
            actions.setdefault((m[1], m[2]), set()).add(rel(p))
    for (act, ver), used in sorted(actions.items()):
        add({"type": "library", "bom-ref": f"action:{act}@{ver}", "name": act, "version": ver,
             "purl": f"pkg:github/{act}@{ver}",
             "properties": prop(kind="github-action", used_in=",".join(sorted(used)),
                                pinned_to_sha=str(bool(re.fullmatch(r"[0-9a-f]{40}", ver))).lower())})

    # ---- Credential names only (never values)
    for p in files:
        if re.fullmatch(r"\.env(\.[\w.-]+)?", os.path.basename(p)) and not p.endswith((".example", ".sample")):
            for line in read(p).splitlines():
                m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
                if m:
                    env_names.add(m.group(1))
    if env_names:
        add({"type": "data", "bom-ref": "credentials", "name": "credentials-referenced",
             "description": "Names only; values are never read or recorded.",
             "properties": prop(names=",".join(sorted(env_names)))})

    top = "app:" + (a.name or os.path.basename(root))
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:" + str(uuid.uuid4()), "version": 1,
           "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "tools": {"components": [{"type": "application", "name": "generate-ai-bom.py"}]},
                        "component": {"type": "application", "bom-ref": top, "name": a.name or os.path.basename(root)},
                        "properties": prop(bom_kind="AI-BOM")},
           "components": comps,
           "dependencies": [{"ref": top, "dependsOn": [c["bom-ref"] for c in comps]}] +
                           [{"ref": r, "dependsOn": d} for r, d in deps.items()]}
    with open(out_abs, "w") as f:
        json.dump(bom, f, indent=2); f.write("\n")
    counts = Counter(c["type"] for c in comps)
    print(f"Wrote {rel(out_abs)}: {len(comps)} components {dict(counts)}")


if __name__ == "__main__":
    sys.exit(main())
