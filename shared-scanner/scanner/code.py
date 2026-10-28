"""
Code scanner using tree-sitter AST analysis.
Detects quantum-vulnerable cryptographic patterns in Python, JavaScript, Java, and Go.

Tree-sitter 0.25 notes:
- Query.captures() / Query.matches() removed — use recursive node walking instead.
- node.start_point returns a namedtuple Point(row, column); both [0] and .row work.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class CodeFinding:
    pattern_id: str
    file_path: str
    line_number: int          # 1-indexed
    code_snippet: str
    algorithm: str
    algorithm_family: str
    quantum_status: str
    algorithm_risk: int
    confidence: str           # high | medium | low
    recommended_replacement: str
    estimated_effort_hours: int
    hndl_risk: bool
    library_name: str = ""
    matched_import: str = ""
    matched_function: str = ""
    matched_string: str = ""


@dataclass
class _FileAST:
    """Collected artefacts for pattern matching."""
    imports: dict[str, int]           # module_path_lower → first line 0-indexed
    calls: dict[str, list[int]]       # func_name → [line, ...]
    strings: dict[str, list[int]]     # string_value → [line, ...]
    lines: list[str]                  # raw source lines


# ---------------------------------------------------------------------------
# Language-specific AST collectors
# ---------------------------------------------------------------------------

def _strip_quotes(s: str) -> str:
    s = s.strip()
    for delim in ('"""', "'''"):
        if s.startswith(delim) and s.endswith(delim) and len(s) >= len(delim) * 2:
            return s[len(delim):-len(delim)]
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'", "`"):
        return s[1:-1]
    return s


# --- Python ---

def _collect_py_imports(node, add_import) -> None:
    """import a, import a.b as x"""
    line = node.start_point[0]
    text = node.text.decode("utf-8", errors="replace").strip()
    body = text[len("import"):].strip()
    for part in body.split(","):
        part = part.strip().split(" as ")[0].strip()
        if part:
            add_import(part, line)


def _collect_py_from_imports(node, add_import) -> None:
    """from a.b import c, d as x, (e, f)"""
    line = node.start_point[0]
    text = node.text.decode("utf-8", errors="replace").strip()
    if " import " not in text:
        return
    after_from = text[len("from"):].strip()
    idx = after_from.find(" import ")
    if idx < 0:
        return
    module = after_from[:idx].strip()
    names_raw = after_from[idx + len(" import "):].strip().strip("()")
    add_import(module, line)
    for name in names_raw.split(","):
        name = name.strip().split(" as ")[0].strip().strip("()")
        if name and name != "*":
            add_import(f"{module}.{name}", line)


def _collect_py_call(node, add_call) -> None:
    """Extract the callable name from a call node."""
    line = node.start_point[0]
    for child in node.children:
        if child.type == "argument_list":
            break
        if child.type == "identifier":
            add_call(child.text.decode("utf-8", errors="replace"), line)
            return
        if child.type == "attribute":
            # a.b.c → want last identifier = "c"
            last_id = None
            for sub in child.children:
                if sub.type == "identifier":
                    last_id = sub
            if last_id:
                add_call(last_id.text.decode("utf-8", errors="replace"), line)
            return


def _collect_py_string(node, add_string) -> None:
    line = node.start_point[0]
    raw = node.text.decode("utf-8", errors="replace")
    # Strip f/b/r prefix characters before quotes
    stripped = raw.lstrip("fFbBrRuU")
    value = _strip_quotes(stripped)
    add_string(value, line)


# --- JavaScript / TypeScript ---

def _collect_js_import(node, add_import) -> None:
    """import x from 'module', import { a } from 'module'"""
    line = node.start_point[0]
    text = node.text.decode("utf-8", errors="replace")
    # Find string literal (the module path)
    for child in node.children:
        if child.type == "string":
            val = _strip_quotes(child.text.decode("utf-8", errors="replace"))
            add_import(val, line)
            return
    # Fallback: extract from text with regex-free scan
    for delim in ('"', "'"):
        start = text.rfind(delim)
        if start >= 0:
            end = text.rfind(delim, 0, start)
            if end >= 0 and end < start:
                add_import(text[end + 1:start], line)
                return


def _collect_js_call_expr(node, add_import, add_call) -> None:
    """call_expression: detect require() and regular function calls."""
    line = node.start_point[0]
    children = list(node.children)
    if not children:
        return
    func_node = children[0]

    # Detect require('module')
    if func_node.type == "identifier" and func_node.text == b"require":
        for child in node.children:
            if child.type == "arguments":
                for arg in child.children:
                    if arg.type == "string":
                        val = _strip_quotes(arg.text.decode("utf-8", errors="replace"))
                        add_import(val, line)
                return
        return

    # Regular call
    if func_node.type == "identifier":
        add_call(func_node.text.decode("utf-8", errors="replace"), line)
    elif func_node.type == "member_expression":
        # jwt.sign → "sign"
        for sub in reversed(func_node.children):
            if sub.type in ("identifier", "property_identifier"):
                add_call(sub.text.decode("utf-8", errors="replace"), line)
                break


def _collect_js_string(node, add_string) -> None:
    line = node.start_point[0]
    raw = node.text.decode("utf-8", errors="replace")
    value = _strip_quotes(raw)
    add_string(value, line)


# --- Java ---

def _collect_java_import(node, add_import) -> None:
    """import org.foo.Bar;  import static org.foo.Bar.METHOD;"""
    line = node.start_point[0]
    text = node.text.decode("utf-8", errors="replace").strip()
    text = text.lstrip("import").strip()
    if text.startswith("static"):
        text = text[len("static"):].strip()
    text = text.rstrip(";").strip().lower()
    if not text:
        return
    add_import(text, line)
    # Add each ancestor package
    parts = text.split(".")
    for i in range(1, len(parts)):
        add_import(".".join(parts[:i]), line)


def _collect_java_method(node, add_call) -> None:
    """method_invocation: extract method name."""
    line = node.start_point[0]
    # Tree-sitter Java: method_invocation has child 'name' (identifier)
    # Often the last identifier before '(' is the name
    last_id = None
    for child in node.children:
        if child.type in ("identifier",):
            last_id = child
        elif child.type == "argument_list":
            break
    if last_id:
        add_call(last_id.text.decode("utf-8", errors="replace"), line)


def _collect_java_string(node, add_string) -> None:
    line = node.start_point[0]
    raw = node.text.decode("utf-8", errors="replace")
    value = _strip_quotes(raw)
    add_string(value, line)


# --- Go ---

def _collect_go_imports_inner(node, add_import) -> None:
    """Recursively find interpreted_string_literals inside import declarations."""
    if node.type == "interpreted_string_literal":
        val = _strip_quotes(node.text.decode("utf-8", errors="replace"))
        add_import(val.lower(), node.start_point[0])
        return
    for child in node.children:
        _collect_go_imports_inner(child, add_import)


def _collect_go_call(node, add_call) -> None:
    """call_expression: rsa.GenerateKey → add 'GenerateKey'."""
    line = node.start_point[0]
    children = list(node.children)
    if not children:
        return
    func_node = children[0]
    if func_node.type == "selector_expression":
        for sub in func_node.children:
            if sub.type == "field_identifier":
                add_call(sub.text.decode("utf-8", errors="replace"), line)
                return
    elif func_node.type == "identifier":
        add_call(func_node.text.decode("utf-8", errors="replace"), line)


def _collect_go_string(node, add_string) -> None:
    line = node.start_point[0]
    raw = node.text.decode("utf-8", errors="replace")
    value = _strip_quotes(raw)
    add_string(value, line)


# ---------------------------------------------------------------------------
# Pattern match helpers
# ---------------------------------------------------------------------------

def _import_matches(file_import: str, pattern_import: str) -> bool:
    """
    True when file_import satisfies pattern_import.
    Handles both specific patterns ("cryptography.hazmat.primitives.asymmetric.rsa")
    and broad ones ("jwt").
    """
    return (
        file_import == pattern_import
        or file_import.startswith(pattern_import + ".")
        or pattern_import.startswith(file_import + ".")
    )


def _find_call_matches(pat_functions: list[str], calls: dict[str, list[int]]) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for func in pat_functions:
        for line in calls.get(func, []):
            results.append((func, line))
    return results


def _is_binary(data: bytes, sample: int = 8192) -> bool:
    """True if data looks like a binary file (null byte or > 30% non-printable)."""
    chunk = data[:sample]
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    printable = bytes(range(32, 127)) + b"\n\r\t\f\b"
    non_text = sum(1 for b in chunk if b not in printable)
    return non_text / len(chunk) > 0.30


def _find_string_matches(pat_strings: list[str], strings: dict[str, list[int]]) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []
    for s in pat_strings:
        for line in strings.get(s, []):
            results.append((s, line))
    return results


# ---------------------------------------------------------------------------
# CodeScanner
# ---------------------------------------------------------------------------

class CodeScanner:
    LANGUAGE_EXTENSIONS: dict[str, str] = {
        ".py": "python",
        ".pyw": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "javascript",
        ".tsx": "javascript",
        ".jsx": "javascript",
        ".java": "java",
        ".go": "go",
    }

    DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset({
        ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
        ".env", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
        "vendor", "third_party", "target", ".gradle",
    })

    def __init__(self, patterns_dir: Optional[Path] = None):
        self._patterns_dir = patterns_dir or (Path(__file__).parent / "patterns")
        self._patterns: dict[str, list[dict]] = {}
        self._parsers: dict[str, object] = {}
        self._load_patterns()
        self._init_parsers()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _load_patterns(self) -> None:
        for lang in ("python", "javascript", "java", "go"):
            path = self._patterns_dir / f"{lang}.json"
            if path.exists():
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                self._patterns[lang] = data.get("patterns", [])
                logger.debug("Loaded %d %s patterns", len(self._patterns[lang]), lang)
            else:
                logger.warning("Pattern file not found: %s", path)

    def _init_parsers(self) -> None:
        try:
            from tree_sitter import Language, Parser
        except ImportError:
            logger.warning("tree-sitter not installed; code scanning disabled")
            return

        _bindings = [
            ("python",     "tree_sitter_python"),
            ("javascript", "tree_sitter_javascript"),
            ("java",       "tree_sitter_java"),
            ("go",         "tree_sitter_go"),
        ]
        for lang_name, module_name in _bindings:
            try:
                mod = __import__(module_name)
                lang_obj = Language(mod.language())
                self._parsers[lang_name] = Parser(lang_obj)
                logger.debug("tree-sitter parser ready: %s", lang_name)
            except Exception as exc:
                logger.warning("tree-sitter %s unavailable: %s", lang_name, exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_directory(
        self,
        path: "Path | str",
        exclude_dirs: Optional[set[str]] = None,
        max_file_size_bytes: int = 5_000_000,
    ) -> list[CodeFinding]:
        root = Path(path)
        if not root.exists():
            raise FileNotFoundError(f"Directory not found: {root}")
        exclude = self.DEFAULT_EXCLUDE_DIRS | (exclude_dirs or set())
        findings: list[CodeFinding] = []
        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in exclude for part in file_path.parts):
                continue
            if file_path.suffix.lower() not in self.LANGUAGE_EXTENSIONS:
                continue
            try:
                if file_path.stat().st_size > max_file_size_bytes:
                    logger.warning("Skipping large file (>%dMB): %s", max_file_size_bytes // 1_000_000, file_path)
                    continue
            except OSError:
                continue
            try:
                findings.extend(self.scan_file(file_path))
            except Exception as exc:
                logger.warning("Failed to scan %s: %s", file_path, exc)
        return findings

    def scan_file(self, path: "Path | str") -> list[CodeFinding]:
        p = Path(path)
        lang = self.LANGUAGE_EXTENSIONS.get(p.suffix.lower())
        if lang is None:
            return []
        try:
            raw = p.read_bytes()
        except OSError as exc:
            logger.warning("Cannot read %s: %s", p, exc)
            return []
        if not raw:
            return []
        if _is_binary(raw):
            logger.debug("Skipping binary file: %s", p)
            return []
        content = raw.decode("utf-8", errors="replace")
        return self.scan_content(content, lang, str(p))

    def scan_content(
        self,
        content: str,
        language: str,
        file_path: str = "<string>",
    ) -> list[CodeFinding]:
        patterns = self._patterns.get(language)
        if not patterns:
            return []
        parser = self._parsers.get(language)
        if parser is None:
            logger.warning("No parser for language: %s", language)
            return []
        if not content.strip():
            return []
        code_bytes = content.encode("utf-8")
        try:
            tree = parser.parse(code_bytes)
        except Exception as exc:
            logger.warning("tree-sitter parse failed for %s: %s", file_path, exc)
            return []
        ast = self._collect_ast(tree.root_node, language, code_bytes)
        return self._match_patterns(patterns, ast, file_path)

    # ------------------------------------------------------------------
    # AST collection
    # ------------------------------------------------------------------

    def _collect_ast(self, root_node, language: str, code_bytes: bytes) -> _FileAST:
        lines = code_bytes.decode("utf-8", errors="replace").splitlines()
        imports: dict[str, int] = {}
        calls: dict[str, list[int]] = {}
        strings: dict[str, list[int]] = {}

        def add_import(path: str, line: int) -> None:
            key = path.strip().lower()
            if key and key not in imports:
                imports[key] = line

        def add_call(name: str, line: int) -> None:
            name = name.strip()
            if name:
                calls.setdefault(name, []).append(line)

        def add_string(value: str, line: int) -> None:
            value = value.strip()
            if value and len(value) <= 100:
                strings.setdefault(value, []).append(line)

        def walk(node) -> None:
            ntype = node.type

            if language == "python":
                if ntype == "import_statement":
                    _collect_py_imports(node, add_import)
                    return
                if ntype == "import_from_statement":
                    _collect_py_from_imports(node, add_import)
                    return
                if ntype == "call":
                    _collect_py_call(node, add_call)
                elif ntype == "string":
                    _collect_py_string(node, add_string)
                    return

            elif language == "javascript":
                if ntype == "import_statement":
                    _collect_js_import(node, add_import)
                    return
                if ntype == "call_expression":
                    _collect_js_call_expr(node, add_import, add_call)
                elif ntype in ("string", "template_string"):
                    _collect_js_string(node, add_string)
                    return

            elif language == "java":
                if ntype == "import_declaration":
                    _collect_java_import(node, add_import)
                    return
                if ntype == "method_invocation":
                    _collect_java_method(node, add_call)
                elif ntype == "string_literal":
                    _collect_java_string(node, add_string)
                    return

            elif language == "go":
                if ntype == "import_declaration":
                    _collect_go_imports_inner(node, add_import)
                    return
                if ntype == "call_expression":
                    _collect_go_call(node, add_call)
                elif ntype == "interpreted_string_literal":
                    _collect_go_string(node, add_string)
                    return

            for child in node.children:
                walk(child)

        walk(root_node)
        return _FileAST(imports=imports, calls=calls, strings=strings, lines=lines)

    # ------------------------------------------------------------------
    # Pattern matching
    # ------------------------------------------------------------------

    def _match_patterns(
        self,
        patterns: list[dict],
        ast: _FileAST,
        file_path: str,
    ) -> list[CodeFinding]:
        findings: list[CodeFinding] = []
        seen: set[tuple[str, int]] = set()

        for pattern in patterns:
            pid = pattern["id"]
            pat_imports = [i.lower() for i in pattern.get("imports", [])]
            pat_functions = pattern.get("functions", [])
            pat_strings = pattern.get("algorithm_strings", [])

            # --- Step 1: check import match ---
            matched_import_str = ""
            import_line = -1
            for pi in pat_imports:
                for file_import, iline in ast.imports.items():
                    if _import_matches(file_import, pi):
                        matched_import_str = pi
                        import_line = iline
                        break
                if matched_import_str:
                    break

            if not matched_import_str and pat_imports:
                # No import match — string-only fallback at medium confidence
                if pat_strings:
                    hndl_so = pattern.get("algorithm_family", "").upper() in ("RSA", "ECC", "DH")
                    for sval, sline in _find_string_matches(pat_strings, ast.strings):
                        key = (pid, sline)
                        if key in seen:
                            continue
                        seen.add(key)
                        snippet = ast.lines[sline].strip() if 0 <= sline < len(ast.lines) else ""
                        findings.append(CodeFinding(
                            pattern_id=pid,
                            file_path=file_path,
                            line_number=sline + 1,
                            code_snippet=snippet,
                            algorithm=pattern.get("algorithm", ""),
                            algorithm_family=pattern.get("algorithm_family", ""),
                            quantum_status=pattern.get("quantum_status", "unknown"),
                            algorithm_risk=pattern.get("algorithm_risk", 5),
                            confidence="medium",
                            recommended_replacement=pattern.get("recommended_replacement", ""),
                            estimated_effort_hours=pattern.get("estimated_effort_hours", 0),
                            hndl_risk=hndl_so,
                            library_name="",
                            matched_import="",
                            matched_function="",
                            matched_string=sval,
                        ))
                continue

            # --- Step 2: determine match lines ---
            # Each match_finding: (line_0indexed, func_str, str_str, confidence)
            match_findings: list[tuple[int, str, str, str]] = []
            base_conf = pattern.get("confidence", "high")

            if pat_functions and pat_strings:
                func_hits = _find_call_matches(pat_functions, ast.calls)
                str_hits = _find_string_matches(pat_strings, ast.strings)
                if func_hits and str_hits:
                    for fname, fline in func_hits:
                        match_findings.append((fline, fname, "", base_conf))
                elif func_hits:
                    for fname, fline in func_hits:
                        match_findings.append((fline, fname, "", "medium"))
                elif str_hits:
                    for sval, sline in str_hits:
                        match_findings.append((sline, "", sval, "medium"))

            elif pat_functions:
                for fname, fline in _find_call_matches(pat_functions, ast.calls):
                    match_findings.append((fline, fname, "", base_conf))

            elif pat_strings:
                for sval, sline in _find_string_matches(pat_strings, ast.strings):
                    match_findings.append((sline, "", sval, base_conf))

            else:
                # import-only
                if import_line >= 0:
                    match_findings.append((import_line, "", "", "medium"))

            # --- Step 3: emit deduplicated findings ---
            hndl = pattern.get("algorithm_family", "").upper() in ("RSA", "ECC", "DH")

            for line_0, mfunc, mstr, conf in match_findings:
                key = (pid, line_0)
                if key in seen:
                    continue
                seen.add(key)
                snippet = ast.lines[line_0].strip() if 0 <= line_0 < len(ast.lines) else ""
                findings.append(CodeFinding(
                    pattern_id=pid,
                    file_path=file_path,
                    line_number=line_0 + 1,
                    code_snippet=snippet,
                    algorithm=pattern.get("algorithm", ""),
                    algorithm_family=pattern.get("algorithm_family", ""),
                    quantum_status=pattern.get("quantum_status", "unknown"),
                    algorithm_risk=pattern.get("algorithm_risk", 5),
                    confidence=conf,
                    recommended_replacement=pattern.get("recommended_replacement", ""),
                    estimated_effort_hours=pattern.get("estimated_effort_hours", 0),
                    hndl_risk=hndl,
                    library_name=matched_import_str,
                    matched_import=matched_import_str,
                    matched_function=mfunc,
                    matched_string=mstr,
                ))

        return findings

    # ------------------------------------------------------------------
    # Pattern library info
    # ------------------------------------------------------------------

    def get_pattern_versions(self) -> dict[str, str]:
        """Return {language: version} for loaded pattern libraries."""
        versions: dict[str, str] = {}
        for lang in ("python", "javascript", "java", "go"):
            path = self._patterns_dir / f"{lang}.json"
            if path.exists():
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                versions[lang] = data.get("version", "unknown")
        return versions

    def get_available_languages(self) -> list[str]:
        return sorted(self._parsers.keys())
