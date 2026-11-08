"""MkDocs hook: builds assets/config-schema.json for the config builder page.

Every key comes from config.yaml (default, and its comments as help), and the
KRAWL_* variable that sets it comes from Config.from_yaml in src/config.py, so
the page follows both files without a hand-kept list.
"""

import ast
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_YAML = ROOT / "config.yaml"
CONFIG_PY = ROOT / "src" / "config.py"

ENUMS = {
    "mode": ["standalone", "scalable"],
    "logging.level": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    "ai.provider": ["openrouter", "openai"],
    "ai.reasoning.effort": ["none", "minimal", "low", "medium", "high", "xhigh"],
}
# Keys config.yaml only shows commented out.
OPTIONAL = {
    "custom_template_path": (None, "Custom honeypot page. Optional {counter} and {content} placeholders."),
    "ai.openai_base_url": (None, 'Endpoint when provider is "openai": OpenAI, or a self-hosted engine such as Ollama or llama.cpp.'),
    "banlist.sources": ([], "Upstream banlist URLs to fetch and merge. Plain .txt lists work too."),
}
PATTERNS = {
    "behavior.error_codes": r"^\s*[1-5]\d\d(\s*,\s*[1-5]\d\d)*\s*$",
}
DURATION = r"^\s*(\d+\s*[hdwmy])?\s*$"
KEY_LINE = re.compile(r"^(\s*)([\w-]+):(.*)$")


def _inline_comment(rest: str) -> str:
    quote = None
    for i, ch in enumerate(rest):
        if quote:
            quote = None if ch == quote else quote
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or rest[i - 1] == " "):
            return rest[i + 1 :].strip()
    return ""


def _help_texts() -> dict[str, str]:
    """Comments above a key, plus its inline comment, keyed by dotted path."""
    helps, pending, stack, block_indent = {}, [], [], None
    for line in CONFIG_YAML.read_text().splitlines():
        indent = len(line) - len(line.lstrip())
        if block_indent is not None:
            if line.strip() and indent <= block_indent:
                block_indent = None
            else:
                continue
        stripped = line.strip()
        if not stripped:
            pending = []
            continue
        if stripped.startswith("#"):
            text = stripped.lstrip("#").strip()
            # Commented-out keys and list items are examples, not help.
            if not KEY_LINE.match(text) and not text.startswith("- "):
                pending.append(text)
            continue
        m = KEY_LINE.match(line)
        if not m:
            continue
        key, rest = m.group(2), m.group(3)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, key))
        path = ".".join(k for _, k in stack)
        text = " ".join(pending + [_inline_comment(rest)]).strip()
        if text:
            helps[path] = text
        pending = []
        if rest.split("#")[0].strip() in ("|", ">", "|-", ">-"):
            block_indent = indent
    return helps


def _env_names(leaves: set[str]) -> dict[str, tuple[str, int]]:
    """Map each config.yaml leaf to (KRAWL_* variable, position in its value)."""
    fn = next(
        n
        for n in ast.walk(ast.parse(CONFIG_PY.read_text()))
        if isinstance(n, ast.FunctionDef) and n.name == "from_yaml"
    )
    sections = {"data": ""}

    def path_of(node):
        if isinstance(node, ast.Name):
            return sections.get(node.id)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            base = path_of(node.func.value)
            return None if base is None else f"{base}.{node.args[0].value}".lstrip(".")
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            base = path_of(node.value)
            return None if base is None else f"{base}.{node.slice.value}".lstrip(".")
        return None

    # `server = data.get("server", {})`, `branding = dashboard.get("branding") or {}`:
    # the outermost .get() in each top-level assignment names a section or leaf.
    for stmt in fn.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
            p = next((p for n in ast.walk(stmt.value) if (p := path_of(n))), None)
            if p:
                sections[stmt.targets[0].id] = p

    call = next(
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "cls"
    )
    envs = {}
    for kw in call.keywords:
        found = []
        for node in ast.walk(kw.value):
            p = path_of(node)
            if p in leaves and p not in found:
                found.append(p)
        for i, p in enumerate(sorted(found, key=lambda p: _order(kw.value, p, path_of))):
            envs.setdefault(p, (f"KRAWL_{kw.arg.upper()}", i))
    return envs


def _order(expr, path, path_of):
    return min(
        (getattr(n, "lineno", 0), getattr(n, "col_offset", 0))
        for n in ast.walk(expr)
        if path_of(n) == path
    )


def _leaves(value, prefix=""):
    if isinstance(value, dict) and value:
        for k, v in value.items():
            yield from _leaves(v, f"{prefix}.{k}".lstrip("."))
    else:
        yield prefix, value


def build_schema() -> list[dict]:
    data = yaml.safe_load(CONFIG_YAML.read_text())
    helps = _help_texts()
    fields = dict(_leaves(data))
    for path, (default, _) in OPTIONAL.items():
        fields.setdefault(path, default)
    envs = _env_names(set(fields))
    out = []
    for path, default in fields.items():
        if isinstance(default, bool):
            kind = "bool"
        elif isinstance(default, (int, float)):
            kind = "number"
        elif isinstance(default, list):
            kind = "numbers" if default and all(type(v) is int for v in default) else "list"
        elif isinstance(default, str) and "\n" in default:
            kind = "text"
        else:
            kind = "string"
        env = envs.get(path)
        field = {
            "path": path,
            "default": default,
            "kind": "enum" if path in ENUMS else kind,
            "help": helps.get(path) or OPTIONAL.get(path, (None, ""))[1],
            "env": env[0] if env else None,
            "envPos": env[1] if env else 0,
        }
        if path in ENUMS:
            field["options"] = ENUMS[path]
        if path.startswith("retention."):
            field["pattern"] = DURATION
        if path in PATTERNS:
            field["pattern"] = PATTERNS[path]
        out.append(field)
    sections = {p: helps[p] for p in helps if "." not in p and isinstance(data.get(p), dict)}
    return {"fields": out, "sections": sections}


def on_post_build(config, **kwargs):
    target = Path(config["site_dir"]) / "assets" / "config-schema.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_schema()))
