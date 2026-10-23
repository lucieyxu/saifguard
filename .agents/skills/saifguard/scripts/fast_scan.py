#!/usr/bin/env python3
"""SAIFGuard Fast Pre-Scanner.

Zero-dependency deterministic scanner for Google SAIF & OWASP Top 10 for LLMs.
Audits Terraform, Python GenAI/RAG code, and Dockerfiles, and runs the hardcoded
credential patterns over common source/config files (JS/TS, Go, Java, YAML, JSON,
notebooks, .env files, ...).
100% offline, zero telemetry.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


def _file_url(path: str | Path, line_number: int) -> str:
    """Build a clickable file:// URL (percent-encoded) for an absolute or CWD-relative path."""
    return f"{Path(path).resolve().as_uri()}#L{line_number}"


@dataclass
class Finding:
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    saif_pillar: str
    owasp_category: str
    file_path: str
    line_number: int
    message: str
    snippet: str = ""
    remediation: str = ""
    title: str = ""
    category: str = "Application & IaC"
    description: str = ""
    location: str = ""
    url: str = ""

    def __post_init__(self):
        if not self.title:
            self.title = self.message.split(".")[0] if self.message else self.rule_id
        if not self.description:
            self.description = self.message
        if not self.location:
            self.location = f"{self.file_path}:{self.line_number}"
        if not self.url and self.file_path:
            # Legacy fallback for callers that build a Finding by hand: the path is resolved against
            # the CWD. SAIFScanner always passes an explicit URL anchored at the scanned file.
            self.url = _file_url(self.file_path, self.line_number)


# Default directories to ignore during traversal
DEFAULT_IGNORES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".terraform",
    "dist",
    "build",
    "site-packages",
    ".ipynb_checkpoints",
    ".tox",
    ".nox",
    "saifguard_reports",
}

# Regex patterns for API keys and credentials (first match wins; one finding per line)
API_KEY_PATTERNS = [
    (re.compile(r"AIzaSy[A-Za-z0-9_-]{33}"), "Google API Key (AIzaSy...)"),
    # Must start a token (not e.g. "high-risk-...") and contain a digit, like real generated keys.
    (
        re.compile(r"(?<![A-Za-z0-9_-])sk-(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{20,}"),
        "OpenAI / Generic Secret Key (sk-...)",
    ),
    (re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"), "PEM Private Key Block"),
    # Python/HCL (`api_key = "..."`), YAML (`api_key: "..."`) and JSON (`"api_key": "..."`) styles.
    (
        re.compile(r"""["']?(?:api_key|apiKey|secret_key|private_key)["']?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]"""),
        "Hardcoded API Key / Secret",
    ),
]

# Non-Python text files that get the SECRET_HARDCODED_API_KEY pass (.py files have their own scanner).
SECRET_SCAN_EXTENSIONS = (
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".sh",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".tf", ".tfvars", ".ipynb",
)
SECRET_SCAN_SKIP_FILES = frozenset(
    {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "go.sum", "Cargo.lock"}
)
MAX_SECRET_SCAN_BYTES = 1024 * 1024  # Skip generated / vendored blobs larger than 1 MB.
_REDACT_RE = re.compile(r"[A-Za-z0-9_+/=-]{12,}")
_MAX_SNIPPET_CHARS = 200

# Fully-qualified call targets that deserialize with (unrestricted) pickle.
PICKLE_FAMILY_CALLS = frozenset({
    "pickle.load", "pickle.loads", "pickle.Unpickler",
    "_pickle.load", "_pickle.loads", "_pickle.Unpickler",
    "cPickle.load", "cPickle.loads", "cPickle.Unpickler",
    "six.moves.cPickle.load", "six.moves.cPickle.loads",
    "dill.load", "dill.loads", "dill.Unpickler",
    "cloudpickle.load", "cloudpickle.loads",
    "joblib.load", "sklearn.externals.joblib.load",
    "pandas.read_pickle",
})
# Used only when the module does not bind these names itself (e.g. snippets, exported notebooks).
CONVENTIONAL_IMPORT_ALIASES = {"np": "numpy", "pd": "pandas"}
TOOL_DECORATOR_NAMES = frozenset({"tool", "agent_tool"})
ADK_RUNNER_CLASSES = frozenset({"Runner", "InMemoryRunner"})
ADK_DEFAULT_MAX_LLM_CALLS = 500  # google.adk.agents.run_config._DEFAULT_MAX_LLM_CALLS

_NOT_CONSTANT = object()


def is_secret_scan_candidate(file_name: str) -> bool:
    """Return True for non-Python text files that should get the hardcoded-credential pass."""
    if file_name in SECRET_SCAN_SKIP_FILES:
        return False
    if file_name == ".env" or file_name.startswith(".env."):
        return True
    return file_name.endswith(SECRET_SCAN_EXTENSIONS)


def _redact_snippet(line: str) -> str:
    return _REDACT_RE.sub("REDACTED", line.strip())[:_MAX_SNIPPET_CHARS]


# Value-level masking for whole file contents that leave the machine (see select_context_files).
_CONTENT_REDACTIONS = [
    (
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
            re.DOTALL,
        ),
        lambda m: "[REDACTED_PRIVATE_KEY]" + "\n" * m.group(0).count("\n"),
    ),
    (API_KEY_PATTERNS[0][0], "[REDACTED_SECRET]"),
    (API_KEY_PATTERNS[1][0], "[REDACTED_SECRET]"),
    (
        re.compile(r"""(["']?(?:api_key|apiKey|secret_key|private_key)["']?\s*[:=]\s*['"])[A-Za-z0-9_\-]{16,}(['"])"""),
        r"\1[REDACTED_SECRET]\2",
    ),
]


def redact_secrets(text: str) -> str:
    """Mask credential values matched by the SECRET_HARDCODED_API_KEY patterns, keeping line structure."""
    for pattern, replacement in _CONTENT_REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def _dotted_name(expr: ast.AST) -> str | None:
    """Return 'a.b.c' for Name/Attribute chains, else None."""
    parts: list[str] = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if isinstance(expr, ast.Name):
        parts.append(expr.id)
        return ".".join(reversed(parts))
    return None


def _collect_imports(tree: ast.AST) -> tuple[dict[str, str], set[str]]:
    """Map local names to fully-qualified import paths and collect imported module names."""
    aliases: dict[str, str] = {}
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases.setdefault(top, top)
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue
            modules.add(node.module)
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases, modules


def _resolve_name(dotted: str, aliases: dict[str, str]) -> str:
    head, _, rest = dotted.partition(".")
    base = aliases.get(head) or CONVENTIONAL_IMPORT_ALIASES.get(head, head)
    return f"{base}.{rest}" if rest else base


def _const_value(node: ast.AST | None) -> Any:
    """Return the literal value of a constant (including negative numbers), else _NOT_CONSTANT."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant):
        value = node.operand.value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return -value
    return _NOT_CONSTANT


def _is_none_literal(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _decorator_name(dec: ast.AST) -> str:
    if isinstance(dec, ast.Call):
        dec = dec.func
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return dec.attr
    return ""


def _parse_image_ref(image_ref: str) -> tuple[str, str]:
    """Classify a Docker image reference as ('digest'|'latest'|'untagged'|'tag', tag)."""
    if "@" in image_ref:
        return "digest", ""
    last_segment = image_ref.rsplit("/", 1)[-1]  # a registry port (host:5000/img) is not a tag
    if ":" in last_segment:
        tag = last_segment.split(":", 1)[1]
        return ("latest", tag) if tag == "latest" else ("tag", tag)
    return "untagged", ""


def _is_root_user(user_spec: str) -> bool:
    user = user_spec.split(":", 1)[0].strip().strip("\"'")
    return user in ("root", "0")


class SAIFScanner:
    """Scans repositories for SAIF and OWASP AI security violations."""

    def __init__(self, root_dir: str | Path, ignore_file: str | Path | None = None):
        self.root_dir = Path(root_dir).resolve()
        self.findings: list[Finding] = []
        self.ignored_rules_by_file: dict[str, set[str]] = {}
        self.ignored_globs: list[str] = []
        self._load_ignore_file(ignore_file)

    def _load_ignore_file(self, ignore_file: str | Path | None) -> None:
        """Load .saifguardignore if present."""
        if not ignore_file:
            potential = self.root_dir / ".saifguardignore"
            if potential.is_file():
                ignore_file = potential

        if ignore_file and Path(ignore_file).is_file():
            for line in Path(ignore_file).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    path_part, rule_part = line.split(":", 1)
                    norm_path = os.path.normpath(path_part.strip())
                    self.ignored_rules_by_file.setdefault(norm_path, set()).add(rule_part.strip())
                else:
                    self.ignored_globs.append(line)

    def _rel(self, file_path: Path) -> str:
        """Path relative to the scan root (falls back to the given path for files outside it)."""
        file_path = Path(file_path)
        try:
            return str(file_path.relative_to(self.root_dir))
        except ValueError:
            try:
                return str(file_path.resolve().relative_to(self.root_dir))
            except ValueError:
                return str(file_path)

    def _add_finding(
        self,
        rule_id: str,
        severity: str,
        saif_pillar: str,
        owasp_category: str,
        file_path: Path,
        line_number: int,
        message: str,
        snippet: str,
        remediation: str,
        lines: list[str] | None,
    ) -> bool:
        """Append a finding unless suppressed; its URL always points at the real file on disk."""
        if lines is not None and self.is_rule_suppressed(rule_id, file_path, line_number, lines):
            return False
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                saif_pillar=saif_pillar,
                owasp_category=owasp_category,
                file_path=self._rel(file_path),
                line_number=line_number,
                message=message,
                snippet=snippet,
                remediation=remediation,
                url=_file_url(file_path, line_number),
            )
        )
        return True

    def is_path_ignored(self, path: Path) -> bool:
        """Check if a file or directory matches ignore rules."""
        rel = self._rel(path)
        for part in path.parts:
            if part in DEFAULT_IGNORES:
                return True
        for glob_pat in self.ignored_globs:
            if fnmatch.fnmatch(rel, glob_pat) or fnmatch.fnmatch(path.name, glob_pat):
                return True
        return False

    def is_rule_suppressed(self, rule_id: str, file_path: Path, line_num: int, lines: list[str]) -> bool:
        """Check if a rule is suppressed via .saifguardignore or inline comments."""
        rel = self._rel(file_path)
        if rel in self.ignored_rules_by_file and rule_id in self.ignored_rules_by_file[rel]:
            return True

        # Check file-level suppression (in the first 10 lines)
        for header_line in lines[:10]:
            if "saifguard:ignore" in header_line:
                match = re.search(r"saifguard:ignore(?:\s+([A-Za-z0-9_]+))?", header_line)
                if match:
                    spec = match.group(1)
                    if not spec or spec == rule_id:
                        return True

        # Check inline comments on the same line or line immediately preceding
        check_lines = []
        if 1 <= line_num <= len(lines):
            check_lines.append(lines[line_num - 1])
        if line_num > 1 and (line_num - 1) <= len(lines):
            check_lines.append(lines[line_num - 2])

        for line in check_lines:
            if "saifguard:ignore" in line:
                match = re.search(r"saifguard:ignore(?:\s+([A-Za-z0-9_]+))?", line)
                if match:
                    specific_rule = match.group(1)
                    if not specific_rule or specific_rule == rule_id:
                        return True
        return False

    def scan(self) -> list[Finding]:
        """Execute scan across all recognized files in the repository."""
        self.findings = []
        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORES and not self.is_path_ignored(Path(root) / d)]
            for file_name in files:
                file_path = Path(root) / file_name
                if self.is_path_ignored(file_path):
                    continue

                if file_name.endswith(".tf"):
                    self.scan_terraform(file_path)
                    self.scan_text_secrets(file_path)
                elif file_name.endswith(".py"):
                    self.scan_python(file_path)
                elif file_name in ("Dockerfile", "Containerfile") or file_name.startswith("Dockerfile."):
                    self.scan_dockerfile(file_path)
                elif is_secret_scan_candidate(file_name):
                    self.scan_text_secrets(file_path)
        return self.findings

    # -------------------------------------------------------------------------
    # Hardcoded Credentials (shared by the Python scanner and the text-file pass)
    # -------------------------------------------------------------------------
    def _scan_secret_lines(self, file_path: Path, lines: list[str]) -> None:
        for idx, line in enumerate(lines, start=1):
            for pat, desc in API_KEY_PATTERNS:
                match = pat.search(line)
                if not match:
                    continue
                snippet = f"{match.group(0)} [REDACTED]" if desc == "PEM Private Key Block" else _redact_snippet(line)
                self._add_finding(
                    "SECRET_HARDCODED_API_KEY",
                    "CRITICAL",
                    "Pillar 6: Contextual Governance",
                    "LLM02: Sensitive Information Disclosure",
                    file_path,
                    idx,
                    f"Hardcoded credential detected: {desc}.",
                    snippet,
                    "Remove secret; use Secret Manager or Vertex AI Application Default Credentials (ADC).",
                    lines,
                )
                break  # one finding per line, even if several patterns match

    def scan_text_secrets(self, file_path: Path) -> None:
        """Run SECRET_HARDCODED_API_KEY over a non-Python text file (skips lockfiles, binaries, > 1 MB)."""
        if file_path.name in SECRET_SCAN_SKIP_FILES:
            return
        try:
            if file_path.stat().st_size > MAX_SECRET_SCAN_BYTES:
                return
            raw = file_path.read_bytes()
        except OSError:
            return
        if b"\x00" in raw[:8192]:
            return
        self._scan_secret_lines(file_path, raw.decode("utf-8", errors="replace").splitlines())

    # -------------------------------------------------------------------------
    # Terraform / IaC Scanner (with Variable & tfvars Resolution)
    # -------------------------------------------------------------------------
    def _load_tf_vars_for_dir(self, dir_path: Path) -> dict[str, Any]:
        """Parse variable defaults, locals, and tfvars within a directory."""
        if not hasattr(self, "_tf_vars_cache"):
            self._tf_vars_cache: dict[Path, dict[str, Any]] = {}
        if dir_path in self._tf_vars_cache:
            return self._tf_vars_cache[dir_path]

        var_map: dict[str, Any] = {}
        if not dir_path.is_dir():
            return var_map

        # 1. Parse variables.tf / *.tf for variable "name" { default = ... }
        var_block_re = re.compile(r'variable\s+"([^"]+)"\s*\{([^}]*)\}', re.MULTILINE | re.DOTALL)
        default_re = re.compile(r'default\s*=\s*([^\n#]+)')
        for tf_file in sorted(dir_path.glob("*.tf")):
            try:
                txt = tf_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in var_block_re.finditer(txt):
                vname = m.group(1)
                body = m.group(2)
                dm = default_re.search(body)
                if dm:
                    raw_val = dm.group(1).strip().strip('"').strip("'")
                    var_map[f"var.{vname}"] = None if raw_val in ("null", "") else raw_val
                else:
                    var_map.setdefault(f"var.{vname}", "__UNSET__")

            # Parse locals { key = value }
            locals_re = re.compile(r'locals\s*\{([^}]*)\}', re.MULTILINE | re.DOTALL)
            for lm in locals_re.finditer(txt):
                for line in lm.group(1).splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, v = line.split("=", 1)
                        clean_v = v.strip().strip('"').strip("'")
                        var_map[f"local.{k.strip()}"] = None if clean_v in ("null", "") else clean_v

        # 2. Parse terraform.tfvars and *.auto.tfvars (overrides defaults)
        tfvars_files = list(dir_path.glob("*.tfvars")) + list(dir_path.glob("*.auto.tfvars"))
        for vf in sorted(tfvars_files):
            try:
                txt = vf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in txt.splitlines():
                line_s = line.strip()
                if not line_s or line_s.startswith("#") or line_s.startswith("//"):
                    continue
                if "=" in line_s:
                    k, v = line_s.split("=", 1)
                    clean_v = v.strip().strip('"').strip("'")
                    var_map[f"var.{k.strip()}"] = None if clean_v in ("null", "") else clean_v

        self._tf_vars_cache[dir_path] = var_map
        return var_map

    def _resolve_tf_attribute(self, block_str: str, attr_names: tuple[str, ...], tf_vars: dict[str, Any]) -> tuple[str, str]:
        """Resolve an HCL attribute against variables/locals into ('VIOLATION' | 'PASS' | 'UNRESOLVED', detail)."""
        for attr in attr_names:
            m = re.search(rf'{attr}\s*=\s*([^\n#]+)', block_str)
            if m:
                raw_expr = m.group(1).strip()
                clean_val = raw_expr.strip('"').strip("'")
                if clean_val in ("null", "", "false"):
                    return "VIOLATION", f"Attribute '{attr}' is explicitly set to null/empty ({raw_expr})."
                if clean_val.startswith("var.") or clean_val.startswith("local."):
                    if clean_val in tf_vars:
                        resolved = tf_vars[clean_val]
                        if resolved is None or resolved == "":
                            return "VIOLATION", f"Attribute '{attr}' references '{clean_val}', which resolves to null/empty."
                        if resolved == "__UNSET__":
                            return "UNRESOLVED", f"Attribute '{attr}' references '{clean_val}' without a default or tfvars value."
                        return "PASS", str(resolved)
                    return "UNRESOLVED", f"Attribute '{attr}' references '{clean_val}' not found in local module vars."
                if clean_val.startswith("data.") or clean_val.startswith("module."):
                    return "UNRESOLVED", f"Attribute '{attr}' references remote data/module output '{clean_val}'."
                return "PASS", clean_val
        return "VIOLATION", "Attribute missing from resource block."

    def scan_terraform(self, file_path: Path) -> None:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        lines = content.splitlines()
        tf_vars = self._load_tf_vars_for_dir(file_path.parent)

        resource_pattern = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE)
        for match in resource_pattern.finditer(content):
            res_type = match.group(1)
            res_name = match.group(2)
            start_pos = match.start()
            line_no = content[:start_pos].count("\n") + 1

            brace_count = 0
            block_content = []
            for line in lines[line_no - 1:]:
                block_content.append(line)
                brace_count += line.count("{") - line.count("}")
                if brace_count <= 0:
                    break
            block_str = "\n".join(block_content)

            # 1. CMEK Encryption Checks (with 3-state variable resolution)
            if res_type in ("google_storage_bucket", "google_sql_database_instance", "google_bigquery_dataset"):
                verdict, detail = self._resolve_tf_attribute(
                    block_str, ("kms_key_name", "default_kms_key_name", "encryption_key_name"), tf_vars
                )
                if verdict == "VIOLATION":
                    self._add_finding(
                        "TF_CMEK_MISSING",
                        "HIGH",
                        "Pillar 1: Strong Foundations",
                        "LLM08: Vector and Embedding Weaknesses",
                        file_path,
                        line_no,
                        f"Resource '{res_type}.{res_name}' lacks Customer-Managed Encryption Keys (CMEK). {detail}",
                        f'resource "{res_type}" "{res_name}"',
                        "Configure CMEK: `encryption { default_kms_key_name = google_kms_crypto_key.key.id }`.",
                        lines,
                    )
                elif verdict == "UNRESOLVED":
                    self._add_finding(
                        "TF_CMEK_UNRESOLVED",
                        "LOW",
                        "Pillar 1: Strong Foundations",
                        "LLM08: Vector and Embedding Weaknesses",
                        file_path,
                        line_no,
                        f"Resource '{res_type}.{res_name}' CMEK key reference could not be statically verified ({detail}). Verify in runtime/CI.",
                        f'resource "{res_type}" "{res_name}"',
                        "Provide a default in `variables.tf` or scan with `saifguard scan --tf-plan plan.json`.",
                        lines,
                    )

            # 2. Cloud Armor WAF Checks
            if res_type == "google_compute_backend_service":
                verdict, detail = self._resolve_tf_attribute(block_str, ("security_policy",), tf_vars)
                if verdict == "VIOLATION":
                    self._add_finding(
                        "TF_CLOUD_ARMOR_MISSING",
                        "HIGH",
                        "Pillar 1: Strong Foundations",
                        "LLM05: Improper Output Handling",
                        file_path,
                        line_no,
                        f"Backend service '{res_name}' has no Cloud Armor 'security_policy' attached. {detail}",
                        f'resource "{res_type}" "{res_name}"',
                        "Attach a Cloud Armor security policy: `security_policy = google_compute_security_policy.policy.id`.",
                        lines,
                    )

        # 3. Overly Permissive IAM Roles & Public Principals (`member = "..."` and `members = [...]`)
        member_public_re = re.compile(r'\bmembers?\s*=[^#\n]*"(?:allUsers|allAuthenticatedUsers)"')
        open_members_list_re = re.compile(r'\bmembers\s*=\s*(?:\w+\(\s*)?\[[^\]]*$')  # e.g. `members = [` / `toset([`
        public_principal_re = re.compile(r'"(?:allUsers|allAuthenticatedUsers)"')
        in_members_list = False
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//")):
                continue
            if re.search(r'role\s*=\s*"roles/(?:editor|owner)"', line):
                self._add_finding(
                    "TF_IAM_OVERPRIVILEGED",
                    "CRITICAL",
                    "Pillar 1: Strong Foundations",
                    "LLM06: Excessive Agency",
                    file_path,
                    idx,
                    "Primitive, overly broad IAM role (roles/editor or roles/owner) assigned.",
                    stripped,
                    "Replace primitive roles with least-privilege fine-grained roles (e.g. roles/aiplatform.user).",
                    lines,
                )
            if in_members_list:
                is_public = bool(public_principal_re.search(line))
                if "]" in line:
                    in_members_list = False
            else:
                is_public = bool(member_public_re.search(line))
                if open_members_list_re.search(line):
                    in_members_list = True  # a multi-line `members = [` list continues on the next lines
            if is_public:
                self._add_finding(
                    "TF_IAM_PUBLIC_ACCESS",
                    "CRITICAL",
                    "Pillar 1: Strong Foundations",
                    "LLM06: Excessive Agency",
                    file_path,
                    idx,
                    "Public unauthenticated access (allUsers or allAuthenticatedUsers) assigned in IAM.",
                    stripped,
                    "Remove public access; restrict binding to designated service accounts or workforce identity.",
                    lines,
                )

    def scan_tf_plan(self, plan_path: str | Path) -> list[Finding]:
        """High-fidelity scan of `terraform show -json plan.out` output."""
        p = Path(plan_path)
        if not p.is_file():
            return self.findings
        try:
            plan_data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return self.findings

        root_module = plan_data.get("planned_values", {}).get("root_module", {})
        resources = root_module.get("resources", [])
        for child in root_module.get("child_modules", []):
            resources.extend(child.get("resources", []))

        for res in resources:
            res_type = res.get("type", "")
            res_name = res.get("name", "")
            values = res.get("values", {}) or {}
            address = res.get("address", f"{res_type}.{res_name}")

            if res_type in ("google_storage_bucket", "google_sql_database_instance", "google_bigquery_dataset"):
                enc = values.get("encryption", [])
                kms = values.get("kms_key_name") or (enc[0].get("default_kms_key_name") if enc and isinstance(enc, list) else None)
                if not kms:
                    self.findings.append(
                        Finding(
                            rule_id="TF_CMEK_MISSING",
                            severity="HIGH",
                            saif_pillar="Pillar 1: Strong Foundations",
                            owasp_category="LLM08: Vector and Embedding Weaknesses",
                            file_path=str(p.name),
                            line_number=1,
                            message=f"Planned resource '{address}' lacks CMEK encryption in resolved Terraform plan.",
                            snippet=address,
                            remediation="Configure CMEK key in Terraform definition.",
                            url=_file_url(p, 1),
                        )
                    )
        return self.findings

    # -------------------------------------------------------------------------
    # Python Scanner (AST & Regex)
    # -------------------------------------------------------------------------
    def scan_python(self, file_path: Path) -> None:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        lines = content.splitlines()

        # 1. Regex check for Secrets
        self._scan_secret_lines(file_path, lines)
        for idx, line in enumerate(lines, start=1):
            if re.search(r"""(?:os\.environ\[['"](?:GEMINI_API_KEY|GOOGLE_API_KEY)['"]\]\s*=)""", line):
                self._add_finding(
                    "SECRET_RAW_API_KEY_ENV",
                    "HIGH",
                    "Pillar 6: Contextual Governance",
                    "LLM02: Sensitive Information Disclosure",
                    file_path,
                    idx,
                    "Raw GEMINI_API_KEY/GOOGLE_API_KEY assigned in code instead of Vertex ADC.",
                    line.strip(),
                    "Migrate enterprise applications from developer API keys to Vertex AI ADC (google-genai vertexai=True).",
                    lines,
                )

        # 2. AST Checks for RAG Multi-Tenancy, Agent Tools, Agent Loop Budgets & Unsafe Deserialization
        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError:
            return

        aliases, imported_modules = _collect_imports(tree)
        imports_adk = any(m == "google.adk" or m.startswith("google.adk.") for m in imported_modules)

        # ADK's per-invocation ceiling is RunConfig(max_llm_calls=N) or the ADK_MAX_LLM_CALLS env var.
        adk_budget_configured = False
        adk_unbounded: list[tuple[int, Any]] = []
        if imports_adk:
            for node in ast.walk(tree):
                value_node = None
                if isinstance(node, ast.keyword) and node.arg == "max_llm_calls":
                    value_node = node.value
                elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if not any(isinstance(t, ast.Attribute) and t.attr == "max_llm_calls" for t in targets):
                        continue
                    value_node = node.value
                elif isinstance(node, ast.Dict):
                    matches = [v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and k.value == "max_llm_calls"]
                    if not matches:
                        continue
                    value_node = matches[-1]
                elif isinstance(node, ast.Constant) and isinstance(node.value, str) and "ADK_MAX_LLM_CALLS" in node.value:
                    adk_budget_configured = True
                    continue
                else:
                    continue
                adk_budget_configured = True
                literal = _const_value(value_node)
                if isinstance(literal, (int, float)) and not isinstance(literal, bool) and literal <= 0:
                    line_no = getattr(value_node, "lineno", None) or getattr(node, "lineno", 1)
                    adk_unbounded.append((line_no, literal))

        for line_no, literal in adk_unbounded:
            self._add_finding(
                "PY_AGENT_NO_MAX_ITER",
                "HIGH",
                "Pillar 4: Harmonized Controls",
                "LLM10: Unbounded Consumption",
                file_path,
                line_no,
                f"ADK RunConfig sets max_llm_calls={literal}; values <= 0 disable ADK's LLM-call ceiling, so a looping agent is unbounded.",
                lines[line_no - 1].strip() if line_no <= len(lines) else "",
                f"Use a positive, workload-sized budget: `run_config=RunConfig(max_llm_calls=<N>)` (ADK default: {ADK_DEFAULT_MAX_LLM_CALLS}).",
                lines,
            )

        class SecurityASTVisitor(ast.NodeVisitor):
            def __init__(self, scanner: SAIFScanner, lines: list[str]):
                self.scanner = scanner
                self.lines = lines

            def _snippet(self, line_no: int) -> str:
                return self.lines[line_no - 1].strip() if line_no <= len(self.lines) else ""

            def _check_deserialization(self, node: ast.Call, qualified: str, line_no: int) -> None:
                kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
                if qualified in PICKLE_FAMILY_CALLS:
                    severity = "CRITICAL"
                    message = f"Insecure deserialization with '{qualified}' (pickle-based) detected; risk of arbitrary code execution."
                elif qualified == "torch.load":
                    weights_only = _const_value(kwargs["weights_only"]) if "weights_only" in kwargs else _NOT_CONSTANT
                    if weights_only is True:
                        return
                    if weights_only is False:
                        severity = "CRITICAL"
                        message = "torch.load(..., weights_only=False) unpickles arbitrary objects; risk of arbitrary code execution."
                    else:
                        # Version-dependent: torch >= 2.6 defaults to weights_only=True, older releases to False.
                        severity = "HIGH"
                        message = (
                            "torch.load() without an explicit weights_only=True runs the full pickle unpickler on "
                            "torch < 2.6 (default weights_only=False); risk of arbitrary code execution."
                        )
                elif qualified == "numpy.load":
                    if _const_value(kwargs.get("allow_pickle")) is not True:
                        return
                    # Opt-in, and unpickling only happens for object arrays stored in the file.
                    severity = "HIGH"
                    message = "numpy.load(..., allow_pickle=True) unpickles object arrays; risk of arbitrary code execution on untrusted files."
                else:
                    return
                self.scanner._add_finding(
                    "PY_UNSAFE_DESERIALIZATION",
                    severity,
                    "Pillar 1: Strong Foundations",
                    "LLM03: Supply Chain Vulnerabilities",
                    file_path,
                    line_no,
                    message,
                    self._snippet(line_no),
                    "Replace pickle-based loading with safe formats (json, safetensors, pydantic); for PyTorch use "
                    "`torch.load(path, weights_only=True)`, for NumPy keep `allow_pickle=False`.",
                    self.lines,
                )

            def _check_agent_budget(self, node: ast.Call, dotted: str, qualified: str, line_no: int) -> None:
                short = qualified.rsplit(".", 1)[-1]
                # (a) Google ADK: Runner has no iteration parameter; the ceiling is RunConfig(max_llm_calls).
                is_adk_runner = imports_adk and short in ADK_RUNNER_CLASSES and (
                    qualified.startswith("google.adk.") or qualified == short
                )
                if is_adk_runner:
                    if not adk_budget_configured:
                        self.scanner._add_finding(
                            "PY_AGENT_NO_MAX_ITER",
                            "MEDIUM",
                            "Pillar 4: Harmonized Controls",
                            "LLM10: Unbounded Consumption",
                            file_path,
                            line_no,
                            f"ADK runner '{short}' relies on the default RunConfig max_llm_calls ceiling of "
                            f"{ADK_DEFAULT_MAX_LLM_CALLS} LLM calls per invocation (or the ADK_MAX_LLM_CALLS env var); "
                            "no explicit max_llm_calls budget is set in this module.",
                            self._snippet(line_no),
                            "Pass an explicit, workload-sized budget on every run: `runner.run_async(user_id=..., "
                            "session_id=..., new_message=..., run_config=RunConfig(max_llm_calls=<N>))` "
                            "(`from google.adk.agents.run_config import RunConfig`). ADK `Runner` has no "
                            "`max_iterations` parameter; values <= 0 disable the limit.",
                            self.lines,
                        )
                    return
                # (b) LangChain AgentExecutor: max_iterations defaults to 15; None without max_execution_time is unbounded.
                if short == "AgentExecutor" or dotted.endswith("AgentExecutor.from_agent_and_tools"):
                    kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
                    if (
                        "max_iterations" in kwargs
                        and _is_none_literal(kwargs["max_iterations"])
                        and ("max_execution_time" not in kwargs or _is_none_literal(kwargs["max_execution_time"]))
                    ):
                        self.scanner._add_finding(
                            "PY_AGENT_NO_MAX_ITER",
                            "HIGH",
                            "Pillar 4: Harmonized Controls",
                            "LLM10: Unbounded Consumption",
                            file_path,
                            line_no,
                            "LangChain AgentExecutor is created with max_iterations=None and no max_execution_time, "
                            "removing the default 15-iteration ceiling (unbounded agent loop).",
                            self._snippet(line_no),
                            "Keep a finite budget: `AgentExecutor(..., max_iterations=15)` (LangChain default) and "
                            "optionally `max_execution_time=<seconds>`.",
                            self.lines,
                        )

            def visit_Call(self, node: ast.Call) -> None:
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                line_no = getattr(node, "lineno", 1)
                dotted = _dotted_name(node.func) or ""
                qualified = _resolve_name(dotted, aliases) if dotted else ""

                # Check for unsafe (pickle-based) deserialization
                if qualified:
                    self._check_deserialization(node, qualified, line_no)

                # Check for RAG Vector Search queries missing tenant isolation filter
                # E.g. vector_store.similarity_search(query) or search(...)
                if func_name in ("similarity_search", "similarity_search_with_score", "find_neighbors"):
                    has_filter = False
                    for kw in node.keywords:
                        if kw.arg in ("filter", "metadata_filter", "filters", "where"):
                            has_filter = True
                            break
                    if not has_filter:
                        self.scanner._add_finding(
                            "PY_RAG_NO_TENANT_FILTER",
                            "CRITICAL",
                            "Pillar 3: Automated Defenses",
                            "LLM08: Vector and Embedding Weaknesses",
                            file_path,
                            line_no,
                            f"Vector search query '{func_name}' lacks tenant/user metadata isolation filter.",
                            self._snippet(line_no),
                            "Add strict multi-tenant metadata filter: `filter={'tenant_id': current_user.tenant_id}`.",
                            self.lines,
                        )

                # Check for agent loops relying on default or disabled loop / LLM-call budgets
                if qualified:
                    self._check_agent_budget(node, dotted, qualified, line_no)

                self.generic_visit(node)

            def _visit_function(self, node: ast.AST) -> None:
                # Check for agent tools (sync or async) exposed without parameter type annotations
                is_tool = any(_decorator_name(dec) in TOOL_DECORATOR_NAMES for dec in node.decorator_list)
                if is_tool:
                    params = list(getattr(node.args, "posonlyargs", [])) + list(node.args.args) + list(node.args.kwonlyargs)
                    untyped_args = [
                        arg.arg for arg in params
                        if arg.arg not in ("self", "cls") and arg.annotation is None
                    ]
                    if untyped_args:
                        line_no = getattr(node, "lineno", 1)
                        self.scanner._add_finding(
                            "PY_AGENT_EXCESSIVE_AGENCY",
                            "HIGH",
                            "Pillar 4: Harmonized Controls",
                            "LLM06: Excessive Agency",
                            file_path,
                            line_no,
                            f"Agent tool '{node.name}' has unvalidated parameters without type constraints: {untyped_args}.",
                            self._snippet(line_no),
                            "Enforce strict typing or Pydantic schema validation on all tool arguments.",
                            self.lines,
                        )
                self.generic_visit(node)

            visit_FunctionDef = _visit_function
            visit_AsyncFunctionDef = _visit_function

        visitor = SecurityASTVisitor(self, lines)
        visitor.visit(tree)

    # -------------------------------------------------------------------------
    # Dockerfile Scanner
    # -------------------------------------------------------------------------
    def scan_dockerfile(self, file_path: Path) -> None:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        lines = content.splitlines()

        # One entry per build stage: base image, optional `AS` alias, FROM line text and its USER directives.
        stages: list[dict[str, Any]] = []
        stage_names: set[str] = set()
        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            # 1. Unpinned Base Image
            from_match = re.match(r"(?i)FROM\s+(.+)$", line_str)
            if from_match:
                tokens = [t for t in from_match.group(1).split() if not t.startswith("--")]  # drop --platform=...
                if not tokens:
                    continue
                image_ref = tokens[0]
                alias = tokens[2].lower() if len(tokens) >= 3 and tokens[1].lower() == "as" else None
                stages.append({"base": image_ref, "alias": alias, "from_text": line_str, "users": []})
                is_stage_ref = image_ref.lower() in stage_names
                if alias:
                    stage_names.add(alias)
                if image_ref.lower() == "scratch" or is_stage_ref or "$" in image_ref:
                    continue  # empty base, earlier build stage, or build-arg-dependent image
                kind, tag = _parse_image_ref(image_ref)
                if kind == "digest":
                    continue
                if kind == "tag":
                    severity = "LOW"
                    message = (
                        f"Base image '{image_ref}' is pinned to the mutable tag ':{tag}' without an immutable "
                        "sha256 digest; the tag can be re-pointed upstream."
                    )
                else:
                    severity = "MEDIUM"
                    message = f"Base image '{image_ref}' uses ':latest' or lacks an immutable sha256 digest pin."
                self._add_finding(
                    "DOCKER_UNPINNED_TAG",
                    severity,
                    "Pillar 4: Harmonized Controls",
                    "LLM03: Supply Chain Vulnerabilities",
                    file_path,
                    idx,
                    message,
                    line_str,
                    "Pin container base image with an immutable digest: `FROM python:3.11-slim@sha256:...`.",
                    lines,
                )
                continue

            # 2. Track USER directives per build stage
            user_match = re.match(r"(?i)USER\s+(\S+)", line_str)
            if user_match and stages:
                stages[-1]["users"].append((idx, line_str, user_match.group(1)))

            # 3. Hardcoded Secret in ENV
            if line_str.upper().startswith("ENV ") and any(k in line_str.lower() for k in ("key", "secret", "token", "password")):
                if "=" in line_str and not line_str.endswith('=""'):
                    self._add_finding(
                        "DOCKER_HARDCODED_SECRET",
                        "CRITICAL",
                        "Pillar 6: Contextual Governance",
                        "LLM02: Sensitive Information Disclosure",
                        file_path,
                        idx,
                        "Potential hardcoded secret or credential embedded in Dockerfile ENV directive.",
                        "ENV [REDACTED_SECRET]",
                        "Do not embed secrets in Docker image layers; inject via Secret Manager at runtime.",
                        lines,
                    )

        if not stages:
            return

        # 4. Root execution: the runtime user is the LAST `USER` of the FINAL stage (inherited from an
        #    earlier stage when the final stage is built `FROM <stage>`).
        def effective_user(stage_idx: int, depth: int = 0) -> tuple[int, str, str] | None:
            stage = stages[stage_idx]
            if stage["users"]:
                return stage["users"][-1]
            parent = stage["base"].lower()
            if depth < len(stages):
                for j in range(stage_idx - 1, -1, -1):
                    if stages[j]["alias"] == parent:
                        return effective_user(j, depth + 1)
            return None

        final_user = effective_user(len(stages) - 1)
        if final_user is None or _is_root_user(final_user[2]):
            if final_user is None:
                message = "Dockerfile lacks a non-root 'USER' directive in its final stage; container will execute as root."
                snippet = stages[-1]["from_text"]
            else:
                message = f"Final stage of the Dockerfile switches to root ('{final_user[1]}'); container will execute as root."
                snippet = final_user[1]
            self._add_finding(
                "DOCKER_ROOT_EXECUTION",
                "HIGH",
                "Pillar 4: Harmonized Controls",
                "LLM06: Excessive Agency",
                file_path,
                len(lines),
                message,
                snippet,
                "Create and switch to a non-root user: `RUN useradd -r appuser && USER appuser`.",
                lines,
            )


# -----------------------------------------------------------------------------
# Smart Context Router & Budgeting (for analysis_tool / LLM Audits)
# -----------------------------------------------------------------------------
AI_HIGH_PRIORITY_KEYWORDS = (
    "vertexai",
    "google.genai",
    "google-genai",
    "langchain",
    "llama_index",
    "pinecone",
    "chromadb",
    "pgvector",
    "@tool",
    "FunctionTool",
    "similarity_search",
    "find_neighbors",
)


def select_context_files(
    root_dir: str | Path,
    max_context_kb: int = 120,
    ignore_file: str | Path | None = None,
) -> dict[str, Any]:
    """Select Tier 1 (full contents), Tier 2 (signatures), and Tier 3 (paths) within a KB budget."""
    root_path = Path(root_dir).resolve()
    scanner = SAIFScanner(root_path, ignore_file=ignore_file)
    findings = scanner.scan()
    flagged_rel_paths = {f.file_path for f in findings}

    tier1_candidates: list[tuple[int, str, str, str]] = []  # (priority, rel_path, content, reason)
    tier2_summaries: list[dict[str, str]] = []
    tier3_paths: list[str] = []

    for root, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORES and not scanner.is_path_ignored(Path(root) / d)]
        for fname in sorted(files):
            fpath = Path(root) / fname
            if scanner.is_path_ignored(fpath):
                continue
            rel = str(fpath.relative_to(root_path))

            if fname.endswith((".py", ".tf", ".yaml", ".yml", ".json", ".md")) or fname in ("Dockerfile", "Containerfile"):
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    tier3_paths.append(rel)
                    continue
                # Files flagged for hardcoded credentials land in Tier 1: never forward the secret values.
                content = redact_secrets(content)

                if rel in flagged_rel_paths:
                    tier1_candidates.append((1, rel, content, "Triggered deterministic security finding"))
                elif fname in ("main.tf", "iam.tf", "network.tf", "Dockerfile", "cloudbuild.yaml"):
                    tier1_candidates.append((2, rel, content, "Core infrastructure / container entrypoint"))
                elif any(kw in content for kw in AI_HIGH_PRIORITY_KEYWORDS):
                    tier1_candidates.append((3, rel, content, "Contains AI / LLM / Vector Search integration"))
                elif fname.endswith(".py"):
                    # Build Tier 2 compact signature summary
                    sigs = []
                    for line in content.splitlines():
                        ls = line.strip()
                        if ls.startswith(("import ", "from ", "def ", "async def ", "class ", "@")):
                            sigs.append(ls[:100])
                    tier2_summaries.append({"path": rel, "summary": "\n".join(sigs[:25])})
                else:
                    tier3_paths.append(rel)
            else:
                tier3_paths.append(rel)

    tier1_candidates.sort(key=lambda item: (item[0], item[1]))
    budget_bytes = max_context_kb * 1024
    used_bytes = 0
    tier1_selected = []
    truncated_files = []

    for _, rel, content, reason in tier1_candidates:
        c_bytes = len(content.encode("utf-8"))
        if used_bytes + c_bytes <= budget_bytes:
            tier1_selected.append({"path": rel, "content": content, "reason": reason})
            used_bytes += c_bytes
        else:
            truncated_files.append(rel)

    return {
        "findings": [asdict(f) for f in findings],
        "tier1_files": tier1_selected,
        "tier2_summaries": tier2_summaries[:30],
        "tier3_paths": tier3_paths[:100],
        "total_kb": round(used_bytes / 1024.0, 2),
        "max_context_kb": max_context_kb,
        "truncated_files": truncated_files,
    }


# -----------------------------------------------------------------------------
# CLI Entrypoint & Formatting
# -----------------------------------------------------------------------------
def format_markdown_summary(findings: list[Finding]) -> str:
    """Render a concise markdown summary for the IDE agent context window."""
    if not findings:
        return "✅ **SAIF Pre-Scan Passed**: No deterministic security violations detected."

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [
        f"⚠️ **SAIF Fast Pre-Scan**: Found {len(findings)} issues ({counts['CRITICAL']} Critical, {counts['HIGH']} High, {counts['MEDIUM']} Medium, {counts['LOW']} Low)",
        "",
        "| Severity | Rule ID | File | Line | Issue |",
        "| :--- | :--- | :--- | :---: | :--- |",
    ]
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.severity) if f.severity in severity_order else 99)

    for f in sorted_findings:
        icon = "🔴" if f.severity == "CRITICAL" else ("🟠" if f.severity == "HIGH" else ("🟡" if f.severity == "MEDIUM" else "🟢"))
        lines.append(f"| {icon} {f.severity} | `{f.rule_id}` | `{f.file_path}` | {f.line_number} | {f.message} |")

    return "\n".join(lines)


def format_sarif_findings(findings: list[Finding]) -> str:
    """Export findings in standard SARIF 2.1.0 format for GitHub / GitLab code scanning."""
    results = []
    for f in findings:
        level = "error" if f.severity in ("CRITICAL", "HIGH") else "warning"
        results.append({
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f"{f.message} Remediation: {f.remediation}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {"startLine": max(f.line_number, 1)},
                    }
                }
            ],
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SAIFGuard Local Security Scanner",
                        "version": "0.2.0",
                        "informationUri": "https://saif.google",
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description="SAIFGuard Deterministic Pre-Scanner")
    parser.add_argument("target", nargs="?", default=".", help="Target repository directory (default: current directory)")
    parser.add_argument("--format", choices=["json", "markdown", "sarif", "summary"], default="markdown", help="Output format")
    parser.add_argument("--output", default=None, help="Write output report to specified file")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None, help="Exit with code 1 if findings meet or exceed severity")
    parser.add_argument("--ignore-file", default=None, help="Custom .saifguardignore file path")
    parser.add_argument("--tf-plan", default=None, help="Optional terraform show -json plan file to scan")
    parser.add_argument("--max-context-kb", type=int, default=120, help="Context budget ceiling in KB")

    args = parser.parse_args()

    scanner = SAIFScanner(args.target, ignore_file=args.ignore_file)
    findings = scanner.scan()
    if args.tf_plan:
        scanner.scan_tf_plan(args.tf_plan)
        findings = scanner.findings

    if args.format == "json":
        out_text = json.dumps([asdict(f) for f in findings], indent=2)
    elif args.format == "sarif":
        out_text = format_sarif_findings(findings)
    elif args.format == "summary":
        out_text = f"Total findings: {len(findings)}"
    else:
        out_text = format_markdown_summary(findings)

    if args.output:
        Path(args.output).write_text(out_text, encoding="utf-8")
        print(f"✓ Saved SAIF Scan Report to: {args.output}")
    else:
        print(out_text)

    if args.fail_on:
        thresholds = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_idx = thresholds.index(args.fail_on)
        for f in findings:
            if f.severity in thresholds and thresholds.index(f.severity) >= min_idx:
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
