#!/usr/bin/env python3
"""SAIFGuard Fast Pre-Scanner.

Zero-dependency deterministic scanner for Google SAIF & OWASP Top 10 for LLMs.
Audits Terraform, Python GenAI/RAG code, and Dockerfiles.
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
            abs_p = Path(self.file_path).resolve()
            self.url = f"file://{abs_p}#L{self.line_number}"


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
}

# Regex patterns for API keys and credentials
API_KEY_PATTERNS = [
    (re.compile(r"AIzaSy[A-Za-z0-9_-]{33}"), "Google API Key (AIzaSy...)"),
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "OpenAI / Generic Secret Key (sk-...)"),
    (re.compile(r"""(?:api_key|apiKey|secret_key|private_key)\s*=\s*['"][A-Za-z0-9_\-]{16,}['"]"""), "Hardcoded API Key / Secret"),
]


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

    def is_path_ignored(self, path: Path) -> bool:
        """Check if a file or directory matches ignore rules."""
        rel = str(path.relative_to(self.root_dir))
        for part in path.parts:
            if part in DEFAULT_IGNORES:
                return True
        for glob_pat in self.ignored_globs:
            if fnmatch.fnmatch(rel, glob_pat) or fnmatch.fnmatch(path.name, glob_pat):
                return True
        return False

    def is_rule_suppressed(self, rule_id: str, file_path: Path, line_num: int, lines: list[str]) -> bool:
        """Check if a rule is suppressed via .saifguardignore or inline comments."""
        rel = str(file_path.relative_to(self.root_dir))
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
                elif file_name.endswith(".py"):
                    self.scan_python(file_path)
                elif file_name in ("Dockerfile", "Containerfile") or file_name.startswith("Dockerfile."):
                    self.scan_dockerfile(file_path)
        return self.findings

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
                    if not self.is_rule_suppressed("TF_CMEK_MISSING", file_path, line_no, lines):
                        self.findings.append(
                            Finding(
                                rule_id="TF_CMEK_MISSING",
                                severity="HIGH",
                                saif_pillar="Pillar 1: Strong Foundations",
                                owasp_category="LLM08: Vector and Embedding Weaknesses",
                                file_path=str(file_path.relative_to(self.root_dir)),
                                line_number=line_no,
                                message=f"Resource '{res_type}.{res_name}' lacks Customer-Managed Encryption Keys (CMEK). {detail}",
                                snippet=f'resource "{res_type}" "{res_name}"',
                                remediation="Configure CMEK: `encryption { default_kms_key_name = google_kms_crypto_key.key.id }`.",
                            )
                        )
                elif verdict == "UNRESOLVED":
                    if not self.is_rule_suppressed("TF_CMEK_UNRESOLVED", file_path, line_no, lines):
                        self.findings.append(
                            Finding(
                                rule_id="TF_CMEK_UNRESOLVED",
                                severity="LOW",
                                saif_pillar="Pillar 1: Strong Foundations",
                                owasp_category="LLM08: Vector and Embedding Weaknesses",
                                file_path=str(file_path.relative_to(self.root_dir)),
                                line_number=line_no,
                                message=f"Resource '{res_type}.{res_name}' CMEK key reference could not be statically verified ({detail}). Verify in runtime/CI.",
                                snippet=f'resource "{res_type}" "{res_name}"',
                                remediation="Provide a default in `variables.tf` or scan with `saifguard scan --tf-plan plan.json`.",
                            )
                        )

            # 2. Cloud Armor WAF Checks
            if res_type == "google_compute_backend_service":
                verdict, detail = self._resolve_tf_attribute(block_str, ("security_policy",), tf_vars)
                if verdict == "VIOLATION":
                    if not self.is_rule_suppressed("TF_CLOUD_ARMOR_MISSING", file_path, line_no, lines):
                        self.findings.append(
                            Finding(
                                rule_id="TF_CLOUD_ARMOR_MISSING",
                                severity="HIGH",
                                saif_pillar="Pillar 1: Strong Foundations",
                                owasp_category="LLM05: Improper Output Handling",
                                file_path=str(file_path.relative_to(self.root_dir)),
                                line_number=line_no,
                                message=f"Backend service '{res_name}' has no Cloud Armor 'security_policy' attached. {detail}",
                                snippet=f'resource "{res_type}" "{res_name}"',
                                remediation="Attach a Cloud Armor security policy: `security_policy = google_compute_security_policy.policy.id`.",
                            )
                        )

        # 3. Overly Permissive IAM Roles
        for idx, line in enumerate(lines, start=1):
            if re.search(r'role\s*=\s*"roles/(?:editor|owner)"', line):
                if not self.is_rule_suppressed("TF_IAM_OVERPRIVILEGED", file_path, idx, lines):
                    self.findings.append(
                        Finding(
                            rule_id="TF_IAM_OVERPRIVILEGED",
                            severity="CRITICAL",
                            saif_pillar="Pillar 1: Strong Foundations",
                            owasp_category="LLM06: Excessive Agency",
                            file_path=str(file_path.relative_to(self.root_dir)),
                            line_number=idx,
                            message="Primitive, overly broad IAM role (roles/editor or roles/owner) assigned.",
                            snippet=line.strip(),
                            remediation="Replace primitive roles with least-privilege fine-grained roles (e.g. roles/aiplatform.user).",
                        )
                    )
            if re.search(r'member\s*=\s*"allUsers"|"allAuthenticatedUsers"', line):
                if not self.is_rule_suppressed("TF_IAM_PUBLIC_ACCESS", file_path, idx, lines):
                    self.findings.append(
                        Finding(
                            rule_id="TF_IAM_PUBLIC_ACCESS",
                            severity="CRITICAL",
                            saif_pillar="Pillar 1: Strong Foundations",
                            owasp_category="LLM06: Excessive Agency",
                            file_path=str(file_path.relative_to(self.root_dir)),
                            line_number=idx,
                            message="Public unauthenticated access (allUsers or allAuthenticatedUsers) assigned in IAM.",
                            snippet=line.strip(),
                            remediation="Remove public access; restrict binding to designated service accounts or workforce identity.",
                        )
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
        for idx, line in enumerate(lines, start=1):
            for pat, desc in API_KEY_PATTERNS:
                if pat.search(line):
                    if not self.is_rule_suppressed("SECRET_HARDCODED_API_KEY", file_path, idx, lines):
                        self.findings.append(
                            Finding(
                                rule_id="SECRET_HARDCODED_API_KEY",
                                severity="CRITICAL",
                                saif_pillar="Pillar 6: Contextual Governance",
                                owasp_category="LLM02: Sensitive Information Disclosure",
                                file_path=str(file_path.relative_to(self.root_dir)),
                                line_number=idx,
                                message=f"Hardcoded credential detected: {desc}.",
                                snippet=re.sub(r"[A-Za-z0-9_-]{12,}", "REDACTED", line.strip()),
                                remediation="Remove secret; use Secret Manager or Vertex AI Application Default Credentials (ADC).",
                            )
                        )
            if re.search(r"""(?:os\.environ\[['"](?:GEMINI_API_KEY|GOOGLE_API_KEY)['"]\]\s*=)""", line):
                if not self.is_rule_suppressed("SECRET_RAW_API_KEY_ENV", file_path, idx, lines):
                    self.findings.append(
                        Finding(
                            rule_id="SECRET_RAW_API_KEY_ENV",
                            severity="HIGH",
                            saif_pillar="Pillar 6: Contextual Governance",
                            owasp_category="LLM02: Sensitive Information Disclosure",
                            file_path=str(file_path.relative_to(self.root_dir)),
                            line_number=idx,
                            message="Raw GEMINI_API_KEY/GOOGLE_API_KEY assigned in code instead of Vertex ADC.",
                            snippet=line.strip(),
                            remediation="Migrate enterprise applications from developer API keys to Vertex AI ADC (google-genai vertexai=True).",
                        )
                    )

        # 2. AST Checks for RAG Multi-Tenancy, Agent Tools & Unsafe Deserialization
        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError:
            return

        class SecurityASTVisitor(ast.NodeVisitor):
            def __init__(self, scanner: SAIFScanner, lines: list[str]):
                self.scanner = scanner
                self.lines = lines

            def visit_Call(self, node: ast.Call) -> None:
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                # Check for unsafe pickle deserialization
                if func_name in ("load", "loads"):
                    if isinstance(node.func, ast.Attribute) and getattr(node.func.value, "id", "") == "pickle":
                        line_no = getattr(node, "lineno", 1)
                        if not self.scanner.is_rule_suppressed("PY_UNSAFE_DESERIALIZATION", file_path, line_no, self.lines):
                            self.scanner.findings.append(
                                Finding(
                                    rule_id="PY_UNSAFE_DESERIALIZATION",
                                    severity="CRITICAL",
                                    saif_pillar="Pillar 1: Strong Foundations",
                                    owasp_category="LLM03: Supply Chain Vulnerabilities",
                                    file_path=str(file_path.relative_to(self.scanner.root_dir)),
                                    line_number=line_no,
                                    message="Insecure deserialization with 'pickle' detected; risk of arbitrary code execution.",
                                    snippet=self.lines[line_no - 1].strip() if line_no <= len(self.lines) else "",
                                    remediation="Replace pickle with safe serialization formats like json, safetensors, or pydantic.",
                                )
                            )

                # Check for RAG Vector Search queries missing tenant isolation filter
                # E.g. vector_store.similarity_search(query) or search(...)
                if func_name in ("similarity_search", "similarity_search_with_score", "find_neighbors"):
                    has_filter = False
                    for kw in node.keywords:
                        if kw.arg in ("filter", "metadata_filter", "filters", "where"):
                            has_filter = True
                            break
                    if not has_filter:
                        line_no = getattr(node, "lineno", 1)
                        if not self.scanner.is_rule_suppressed("PY_RAG_NO_TENANT_FILTER", file_path, line_no, self.lines):
                            self.scanner.findings.append(
                                Finding(
                                    rule_id="PY_RAG_NO_TENANT_FILTER",
                                    severity="CRITICAL",
                                    saif_pillar="Pillar 3: Automated Defenses",
                                    owasp_category="LLM08: Vector and Embedding Weaknesses",
                                    file_path=str(file_path.relative_to(self.scanner.root_dir)),
                                    line_number=line_no,
                                    message=f"Vector search query '{func_name}' lacks tenant/user metadata isolation filter.",
                                    snippet=self.lines[line_no - 1].strip() if line_no <= len(self.lines) else "",
                                    remediation="Add strict multi-tenant metadata filter: `filter={'tenant_id': current_user.tenant_id}`.",
                                )
                            )

                # Check for agent loops missing max_iterations / budget bounds
                if func_name in ("Runner", "AgentRunner", "create_react_agent", "AgentEngine"):
                    has_max_iter = any(kw.arg in ("max_iterations", "max_steps", "step_limit") for kw in node.keywords)
                    if not has_max_iter:
                        line_no = getattr(node, "lineno", 1)
                        if not self.scanner.is_rule_suppressed("PY_AGENT_NO_MAX_ITER", file_path, line_no, self.lines):
                            self.scanner.findings.append(
                                Finding(
                                    rule_id="PY_AGENT_NO_MAX_ITER",
                                    severity="MEDIUM",
                                    saif_pillar="Pillar 4: Harmonized Controls",
                                    owasp_category="LLM10: Unbounded Consumption",
                                    file_path=str(file_path.relative_to(self.scanner.root_dir)),
                                    line_number=line_no,
                                    message=f"Agent runtime '{func_name}' initialized without explicit 'max_iterations' ceiling.",
                                    snippet=self.lines[line_no - 1].strip() if line_no <= len(self.lines) else "",
                                    remediation="Configure execution limit: `max_iterations=15` to prevent denial-of-wallet loops.",
                                )
                            )

                self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                # Check for agent tools exposed without type annotations or docstrings
                is_tool = False
                for dec in node.decorator_list:
                    dec_name = ""
                    if isinstance(dec, ast.Name):
                        dec_name = dec.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    elif isinstance(dec, ast.Call) and isinstance(dec.func, (ast.Name, ast.Attribute)):
                        dec_name = dec.func.id if isinstance(dec.func, ast.Name) else dec.func.attr
                    if dec_name in ("tool", "agent_tool", "command"):
                        is_tool = True
                        break

                if is_tool:
                    # Check if parameters have type annotations
                    untyped_args = [
                        arg.arg for arg in node.args.args
                        if arg.arg != "self" and arg.annotation is None
                    ]
                    if untyped_args:
                        line_no = getattr(node, "lineno", 1)
                        if not self.scanner.is_rule_suppressed("PY_AGENT_EXCESSIVE_AGENCY", file_path, line_no, self.lines):
                            self.scanner.findings.append(
                                Finding(
                                    rule_id="PY_AGENT_EXCESSIVE_AGENCY",
                                    severity="HIGH",
                                    saif_pillar="Pillar 4: Harmonized Controls",
                                    owasp_category="LLM06: Excessive Agency",
                                    file_path=str(file_path.relative_to(self.scanner.root_dir)),
                                    line_number=line_no,
                                    message=f"Agent tool '{node.name}' has unvalidated parameters without type constraints: {untyped_args}.",
                                    snippet=self.lines[line_no - 1].strip() if line_no <= len(self.lines) else "",
                                    remediation="Enforce strict typing or Pydantic schema validation on all tool arguments.",
                                )
                            )
                self.generic_visit(node)

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

        has_user_directive = False
        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            # 1. Unpinned Base Image
            if line_str.upper().startswith("FROM "):
                image_ref = line_str.split()[1]
                if image_ref != "scratch" and ("latest" in image_ref or (":" not in image_ref and "@" not in image_ref)):
                    if not self.is_rule_suppressed("DOCKER_UNPINNED_TAG", file_path, idx, lines):
                        self.findings.append(
                            Finding(
                                rule_id="DOCKER_UNPINNED_TAG",
                                severity="MEDIUM",
                                saif_pillar="Pillar 4: Harmonized Controls",
                                owasp_category="LLM03: Supply Chain Vulnerabilities",
                                file_path=str(file_path.relative_to(self.root_dir)),
                                line_number=idx,
                                message=f"Base image '{image_ref}' uses ':latest' or lacks an immutable sha256 digest pin.",
                                snippet=line_str,
                                remediation="Pin container base image with an immutable digest: `FROM python:3.11-slim@sha256:...`.",
                            )
                        )

            # 2. Check for USER directive
            if line_str.upper().startswith("USER "):
                user_val = line_str.split()[1]
                if user_val not in ("0", "root"):
                    has_user_directive = True

            # 3. Hardcoded Secret in ENV
            if line_str.upper().startswith("ENV ") and any(k in line_str.lower() for k in ("key", "secret", "token", "password")):
                if "=" in line_str and not line_str.endswith('=""'):
                    if not self.is_rule_suppressed("DOCKER_HARDCODED_SECRET", file_path, idx, lines):
                        self.findings.append(
                            Finding(
                                rule_id="DOCKER_HARDCODED_SECRET",
                                severity="CRITICAL",
                                saif_pillar="Pillar 6: Contextual Governance",
                                owasp_category="LLM02: Sensitive Information Disclosure",
                                file_path=str(file_path.relative_to(self.root_dir)),
                                line_number=idx,
                                message="Potential hardcoded secret or credential embedded in Dockerfile ENV directive.",
                                snippet="ENV [REDACTED_SECRET]",
                                remediation="Do not embed secrets in Docker image layers; inject via Secret Manager at runtime.",
                            )
                        )

        if not has_user_directive:
            last_line = len(lines)
            if not self.is_rule_suppressed("DOCKER_ROOT_EXECUTION", file_path, last_line, lines):
                self.findings.append(
                    Finding(
                        rule_id="DOCKER_ROOT_EXECUTION",
                        severity="HIGH",
                        saif_pillar="Pillar 4: Harmonized Controls",
                        owasp_category="LLM06: Excessive Agency",
                        file_path=str(file_path.relative_to(self.root_dir)),
                        line_number=last_line,
                        message="Dockerfile lacks a non-root 'USER' directive; container will execute as root.",
                        snippet="FROM ...",
                        remediation="Create and switch to a non-root user: `RUN useradd -r appuser && USER appuser`.",
                    )
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
