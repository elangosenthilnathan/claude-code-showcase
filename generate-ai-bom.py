#!/usr/bin/env python3
"""Generate a CycloneDX 1.6 AI-BOM for a repository (standard library only).

Usage:  python3 generate-ai-bom.py [REPO_PATH] [-o ai-bom.cdx.json] [--name NAME] [--format json|xml|both]

Output format: json (default), xml (CycloneDX XML, e.g. for Qwiet --bom-path), or both.
With xml, the default output name becomes ai-bom.cdx.xml; with both, -o gives the base name.

Detects: LLM model references, agents, skills, slash commands, hooks, MCP servers,
GitHub Actions, and credential NAMES (values are never read or written).
It reflects only what is declared in the repo; it does not verify packages.
"""
import argparse, datetime, hashlib, json, os, re, sys, uuid
import xml.etree.ElementTree as ET
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


NS = "http://cyclonedx.org/schema/bom/1.6"
# Child order required by the CycloneDX 1.6 XSD sequences
COMP_ORDER = ["supplier", "author", "publisher", "group", "name", "version", "description", "scope",
              "hashes", "licenses", "copyright", "cpe", "purl", "properties"]


def _text(parent, tag, value):
    e = ET.SubElement(parent, f"{{{NS}}}{tag}"); e.text = str(value); return e


def _props(parent, props):
    if props:
        pe = ET.SubElement(parent, f"{{{NS}}}properties")
        for p in props:
            ET.SubElement(pe, f"{{{NS}}}property", name=p["name"]).text = str(p["value"])


def _component(parent, c, tag="component"):
    e = ET.SubElement(parent, f"{{{NS}}}{tag}", {"type": c["type"], **({"bom-ref": c["bom-ref"]} if "bom-ref" in c else {})})
    for key in COMP_ORDER:
        v = c.get(key)
        if not v:
            continue
        if key == "supplier":
            _text(ET.SubElement(e, f"{{{NS}}}supplier"), "name", v["name"])
        elif key == "hashes":
            he = ET.SubElement(e, f"{{{NS}}}hashes")
            for h in v:
                ET.SubElement(he, f"{{{NS}}}hash", alg=h["alg"]).text = h["content"]
        elif key == "properties":
            _props(e, v)
        else:
            _text(e, key, v)
    return e


def bom_to_xml(bom):
    """Convert the CycloneDX 1.6 JSON structure produced above into CycloneDX 1.6 XML."""
    ET.register_namespace("", NS)
    root = ET.Element(f"{{{NS}}}bom", {"serialNumber": bom["serialNumber"], "version": str(bom["version"])})
    md, mde = bom["metadata"], ET.SubElement(root, f"{{{NS}}}metadata")
    _text(mde, "timestamp", md["timestamp"])
    tools = ET.SubElement(ET.SubElement(mde, f"{{{NS}}}tools"), f"{{{NS}}}components")
    for t in md["tools"]["components"]:
        _component(tools, t)
    _component(mde, md["component"])
    _props(mde, md.get("properties"))
    ce = ET.SubElement(root, f"{{{NS}}}components")
    for c in bom["components"]:
        _component(ce, c)
    de = ET.SubElement(root, f"{{{NS}}}dependencies")
    for d in bom["dependencies"]:
        dep = ET.SubElement(de, f"{{{NS}}}dependency", ref=d["ref"])
        for r in d.get("dependsOn", []):
            ET.SubElement(dep, f"{{{NS}}}dependency", ref=r)
    tree = ET.ElementTree(root); ET.indent(tree, space="  ")
    return tree


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("-o", "--output", help="output file (default ai-bom.cdx.json, or ai-bom.cdx.xml with --format xml)")
    ap.add_argument("--format", choices=["json", "xml", "both"], default="json", help="output format (default: json)")
    ap.add_argument("--name", help="application name (default: folder name)")
    a = ap.parse_args()
    root = os.path.abspath(a.path)
    out_abs = os.path.abspath(a.output or ("ai-bom.cdx.xml" if a.format == "xml" else "ai-bom.cdx.json"))
    base_abs = re.sub(r"\.(json|xml)$", "", out_abs)
    rel = lambda p: os.path.relpath(p, root).replace(os.sep, "/")
    comps, deps, seen = [], {}, set()

    def add(c, depends=None):
        if c["bom-ref"] in seen:
            return
        seen.add(c["bom-ref"]); comps.append(c)
        if depends:
            deps[c["bom-ref"]] = depends

    files = [p for p in walk(root) if not os.path.abspath(p).startswith(base_abs + ".")]

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
    written = []
    if a.format in ("json", "both"):
        path = base_abs + ".json" if a.format == "both" else out_abs
        with open(path, "w") as f:
            json.dump(bom, f, indent=2); f.write("\n")
        written.append(path)
    if a.format in ("xml", "both"):
        path = base_abs + ".xml" if a.format == "both" else out_abs
        bom_to_xml(bom).write(path, encoding="utf-8", xml_declaration=True)
        written.append(path)
    counts = Counter(c["type"] for c in comps)
    print(f"Wrote {', '.join(rel(w) for w in written)}: {len(comps)} components {dict(counts)}")


if __name__ == "__main__":
    sys.exit(main())
