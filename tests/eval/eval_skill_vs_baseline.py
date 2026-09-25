#!/usr/bin/env python3
"""SAIFGuard Skill vs. Baseline Gemini A/B Evaluation & Blinded LLM-as-a-Judge Benchmark.

Compares:
  - Baseline: Raw Gemini prompted to audit a GCP project / repository / design doc according to Google SAIF.
  - Treatment: Gemini equipped with the SAIFGuard Skill (Step 1 deterministic scanners + Step 2 progressive
    disclosure reference rulebooks + Step 4 structured report template).

Scoring Architecture (Hybrid 50/50):
  1. Layer 1 — Deterministic Ground-Truth Scorer (50% weight):
     - Ground-truth vulnerability recall rate (0-100%)
     - GA command hygiene (penalizes `gcloud alpha` / `gcloud beta`)
     - Evidence grounding (clickable `https://console.cloud.google.com/...` or `file:///...` links)
     - Cloud-to-Code Drift & Visibility Matrix detection
  2. Layer 2 — Blinded Pairwise LLM-as-a-Judge (50% weight):
     - Randomized candidate order (Candidate 1 vs Candidate 2) to prevent position/label bias
     - 5-dimension SAIF engineering rubric (1-5 scale each, normalized to 0-100%)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
SKILL_DIR = SRC_DIR / "saifguard" / "skills" / "saifguard"
SCRIPTS_DIR = SKILL_DIR / "scripts"
REFS_DIR = SKILL_DIR / "references"
RESOURCES_DIR = SKILL_DIR / "resources"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

for p in (SRC_DIR, SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


@dataclass
class GroundTruthItem:
    """A planted or discovered ground-truth vulnerability that an audit report should detect."""

    rule_id: str
    description: str
    required_resource_or_file: str
    concept_keywords: list[str]


@dataclass
class DeterministicScore:
    """Objective programmatic evaluation of an audit report."""

    recall_pct: float
    matched_rules: list[str]
    missed_rules: list[str]
    ga_command_hygiene_pct: float
    alpha_beta_violations: list[str]
    evidence_grounding_pct: float
    drift_and_visibility_pct: float
    total_deterministic_score: float


@dataclass
class JudgeRubricScore:
    """Blinded LLM-as-a-Judge evaluation across 5 SAIF criteria (1-5 scale each)."""

    saif_owasp_mapping: int = 0
    technical_depth_and_accuracy: int = 0
    cloud_to_code_drift_and_visibility: int = 0
    remediation_executability: int = 0
    signal_to_noise_and_structure: int = 0
    rationale: str = ""

    @property
    def normalized_pct(self) -> float:
        total = (
            self.saif_owasp_mapping
            + self.technical_depth_and_accuracy
            + self.cloud_to_code_drift_and_visibility
            + self.remediation_executability
            + self.signal_to_noise_and_structure
        )
        return round((total / 25.0) * 100.0, 1)


# ---------------------------------------------------------------------------
# Default Ground-Truth Checklist for the Fixture Benchmark Suite
# ---------------------------------------------------------------------------
FIXTURE_GROUND_TRUTH: list[GroundTruthItem] = [
    GroundTruthItem(
        rule_id="GCP_SAIF_VERTEX_ENDPOINT_NO_CMEK",
        description="Vertex AI Endpoint '987654321' (gemini-rag-endpoint) lacks CMEK encryptionSpec.kmsKeyName",
        required_resource_or_file="987654321",
        concept_keywords=["cmek", "kms", "encryptionspec"],
    ),
    GroundTruthItem(
        rule_id="GCP_SAIF_STORAGE_NO_CMEK_OR_PUBLIC",
        description="GCS bucket 'vertex-rag-embeddings-prod' lacks CMEK encryption or has overly permissive access",
        required_resource_or_file="vertex-rag-embeddings-prod",
        concept_keywords=["cmek", "kms", "encryption", "allusers", "public"],
    ),
    GroundTruthItem(
        rule_id="GCP_SAIF_LB_NO_CLOUD_ARMOR",
        description="External BackendService 'ai-gateway-backend' lacks a Cloud Armor securityPolicy",
        required_resource_or_file="ai-gateway-backend",
        concept_keywords=["cloud armor", "securitypolicy", "waf"],
    ),
    GroundTruthItem(
        rule_id="GCP_SAIF_SA_USER_MANAGED_KEY",
        description="Service account 'sa@ale-test-network.iam.gserviceaccount.com' uses a static USER_MANAGED key",
        required_resource_or_file="sa@ale-test-network.iam.gserviceaccount.com",
        concept_keywords=["user_managed", "key", "workload identity", "adc"],
    ),
    GroundTruthItem(
        rule_id="GCP_SAIF_MODEL_ARMOR_NOT_CONFIGURED",
        description="No Vertex AI Model Armor prompt injection / DLP guardrail templates configured",
        required_resource_or_file="model armor",
        concept_keywords=["modelarmor", "model armor", "guardrail", "floorsetting"],
    ),
    GroundTruthItem(
        rule_id="CLOUD_TO_CODE_SHADOW_AI_DRIFT",
        description="Shadow AI / ClickOps drift: live Vertex Endpoint 987654321 or ai-gateway-backend missing from local Terraform",
        required_resource_or_file="storage_no_cmek.tf",
        concept_keywords=["drift", "shadow ai", "clickops", "unmanaged", "missing from local"],
    ),
    GroundTruthItem(
        rule_id="SAIF_PILLAR3_RAG_UNFILTERED_SEARCH",
        description="Unfiltered vector search in unfiltered_vector_search.py (similarity_search without tenant filter)",
        required_resource_or_file="unfiltered_vector_search.py",
        concept_keywords=["similarity_search", "filter", "tenant"],
    ),
    GroundTruthItem(
        rule_id="SAIF_PILLAR4_AGENT_INFINITE_LOOP",
        description="Unbounded agent execution loop in infinite_agent_loop.py without max_iterations budget",
        required_resource_or_file="infinite_agent_loop.py",
        concept_keywords=["while true", "infinite", "max_iterations", "budget"],
    ),
]


# ---------------------------------------------------------------------------
# Layer 1: Deterministic Ground-Truth Scorer
# ---------------------------------------------------------------------------
def score_report_deterministically(
    report_md: str,
    ground_truth: list[GroundTruthItem],
) -> DeterministicScore:
    """Programmatically evaluate a report on Recall, GA Command Hygiene, Grounding, and Drift."""
    lower_md = report_md.lower()

    # 1. Ground-Truth Recall
    matched: list[str] = []
    missed: list[str] = []
    for item in ground_truth:
        has_target = item.required_resource_or_file.lower() in lower_md
        has_concept = any(kw.lower() in lower_md for kw in item.concept_keywords)
        if has_target and has_concept:
            matched.append(item.rule_id)
        else:
            missed.append(item.rule_id)

    recall_pct = round((len(matched) / max(len(ground_truth), 1)) * 100.0, 1)

    # 2. GA Command Hygiene (zero `gcloud alpha` / `gcloud beta` + presence of actionable gcloud/diff blocks)
    alpha_beta_matches = re.findall(r"gcloud\s+(?:alpha|beta)\s+[a-z0-9_-]+", lower_md)
    has_gcloud_or_diff = bool(re.search(r"```(?:bash|sh|diff|hcl|terraform)", lower_md))
    if alpha_beta_matches:
        ga_hygiene = max(0.0, 100.0 - (len(alpha_beta_matches) * 35.0))
    else:
        ga_hygiene = 100.0 if has_gcloud_or_diff else 40.0

    # 3. Evidence Grounding (clickable Console URLs, file:/// links, SAIF Pillar & OWASP citations)
    score_parts = 0.0
    if "https://console.cloud.google.com/" in report_md:
        score_parts += 35.0
    if "file:///" in report_md or re.search(r"\.py[:#]L?\d+", report_md):
        score_parts += 25.0
    if re.search(r"pillar\s*[1-6]", lower_md):
        score_parts += 20.0
    if re.search(r"llm0[1-9]|llm10", lower_md):
        score_parts += 20.0
    evidence_grounding_pct = round(min(100.0, score_parts), 1)

    # 4. Cloud-to-Code Drift & API Visibility Matrix Coverage
    drift_vis_score = 0.0
    if any(k in lower_md for k in ("shadow ai", "clickops", "cloud-to-code", "drift")):
        drift_vis_score += 50.0
    if any(k in lower_md for k in ("visibility", "coverage", "permission_denied", "service_disabled", "scanned")):
        drift_vis_score += 50.0

    # Weighted deterministic total (50% recall, 20% GA hygiene, 15% grounding, 15% drift/visibility)
    total_det = round(
        (recall_pct * 0.50)
        + (ga_hygiene * 0.20)
        + (evidence_grounding_pct * 0.15)
        + (drift_vis_score * 0.15),
        1,
    )

    return DeterministicScore(
        recall_pct=recall_pct,
        matched_rules=matched,
        missed_rules=missed,
        ga_command_hygiene_pct=round(ga_hygiene, 1),
        alpha_beta_violations=alpha_beta_matches,
        evidence_grounding_pct=evidence_grounding_pct,
        drift_and_visibility_pct=round(drift_vis_score, 1),
        total_deterministic_score=total_det,
    )


# ---------------------------------------------------------------------------
# Gemini Client Wrapper (Supports gcloud mTLS Session + google-genai SDK)
# ---------------------------------------------------------------------------
def _get_gcloud_session():
    """Load googlecloudsdk authenticated session (supports mTLS/ECP on corporate workstations)."""
    try:
        sdk_root = None
        if os.environ.get("CLOUDSDK_HOME"):
            sdk_root = Path(os.environ["CLOUDSDK_HOME"])
        elif shutil.which("gcloud"):
            sdk_root = Path(shutil.which("gcloud")).resolve().parent.parent
        if sdk_root and (sdk_root / "lib").is_dir():
            for sub in (sdk_root / "lib", sdk_root / "lib" / "third_party"):
                if str(sub) not in sys.path:
                    sys.path.append(str(sub))
            from googlecloudsdk.core.credentials import requests as creds_requests
            from googlecloudsdk.core.credentials import store

            store.LoadIfEnabled()
            return creds_requests.GetSession()
    except Exception:
        pass
    return None


def call_gemini(
    prompt: str,
    system_instruction: str = "",
    model: str = "gemini-3.8-flash",
    temperature: float = 0.1,
    project_id: str | None = None,
) -> str:
    """Invoke Gemini via gcloud mTLS session (Vertex AI) or google-genai SDK with retry."""
    import time

    active_project = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not active_project:
        try:
            proc = subprocess.run(
                ["gcloud", "config", "get-value", "project"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                active_project = proc.stdout.strip()
        except Exception:
            pass

    # 1. Try gcloud mTLS/ECP Vertex AI REST session first (zero-config on corporate macOS)
    session = _get_gcloud_session()
    if session is not None and active_project:
        payload: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": temperature},
        }
        if system_instruction:
            payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

        for attempt in range(3):
            for host in ("https://aiplatform.mtls.googleapis.com", "https://aiplatform.googleapis.com"):
                url = f"{host}/v1/projects/{active_project}/locations/global/publishers/google/models/{model}:generateContent"
                try:
                    resp = session.post(url, json=payload, timeout=180)
                    if resp.status_code == 200:
                        data = resp.json()
                        parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                        text = "".join(p.get("text", "") for p in parts if "text" in p)
                        if text:
                            return text
                except Exception:
                    continue
            time.sleep(2 ** attempt)

    # 2. Fallback to google-genai SDK
    from google import genai
    from google.genai import types

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    client = genai.Client(api_key=api_key) if api_key else genai.Client(vertexai=True, project=active_project, location="global")
    cfg = types.GenerateContentConfig(
        system_instruction=system_instruction or None,
        temperature=temperature,
    )
    response = client.models.generate_content(model=model, contents=prompt, config=cfg)
    return response.text or ""


# ---------------------------------------------------------------------------
# Layer 2: Blinded Pairwise LLM-as-a-Judge
# ---------------------------------------------------------------------------
def run_blinded_llm_judge(
    baseline_report: str,
    skill_report: str,
    target_summary: str,
    model: str = "gemini-3.8-flash",
    project_id: str | None = None,
    seed: int = 42,
) -> tuple[JudgeRubricScore, JudgeRubricScore, str]:
    """Run a blinded pairwise LLM-as-a-Judge evaluation with randomized candidate ordering."""
    rng = random.Random(seed)
    swap = rng.choice([True, False])
    if swap:
        cand_1_label, cand_1_text = "SAIFGuard_Skill", skill_report
        cand_2_label, cand_2_text = "Baseline_Gemini", baseline_report
    else:
        cand_1_label, cand_1_text = "Baseline_Gemini", baseline_report
        cand_2_label, cand_2_text = "SAIFGuard_Skill", skill_report

    judge_system = (
        "You are an impartial Principal AI Security Auditor acting as an LLM-as-a-Judge. "
        "You are comparing two anonymized security audit reports (Candidate_1 and Candidate_2) "
        "that evaluated the same target system against Google's Secure AI Framework (SAIF) and OWASP LLM Top 10.\n"
        "Do NOT favor verbosity for its own sake; reward factual precision, detection of concrete resource/code "
        "vulnerabilities, Cloud-to-Code drift detection, API visibility gap reporting, and copy-pasteable GA `gcloud` "
        "(never alpha/beta) or git diff remediations."
    )

    judge_prompt = f"""Evaluate `Candidate_1` and `Candidate_2` on a 1 to 5 integer scale (1=Poor, 3=Adequate, 5=Exceptional) across each of the 5 criteria below:

1. `saif_owasp_mapping`: Precision of mapping each finding to specific Google SAIF Pillars (1-6) and OWASP Top 10 for LLMs (LLM01-LLM10).
2. `technical_depth_and_accuracy`: Detection of specific AI/ML security flaws (missing Vertex CMEK, public RAG bucket, plaintext API keys in Cloud Run, missing DATA_READ audit logs, Model Armor, unfiltered vector search, unbounded agent loops).
3. `cloud_to_code_drift_and_visibility`: Explicit detection of Cloud-to-Code drift (Shadow AI / ClickOps cloud resources missing from local Terraform) and GCP API visibility/coverage reporting.
4. `remediation_executability`: Immediate copy-paste readiness of General Availability (GA) `gcloud` commands (penalize `gcloud alpha` or `gcloud beta` or generic `<YOUR_RESOURCE>` placeholders) and unified code diffs.
5. `signal_to_noise_and_structure`: Strict severity ordering (Critical -> High -> Medium -> Low), clickable resource/file links, and absence of generic non-AI filler.

### Target Scope Summary
{target_summary[:3000]}

---
### Candidate_1 Report
{cand_1_text[:18000]}

---
### Candidate_2 Report
{cand_2_text[:18000]}

Respond ONLY with valid JSON matching this exact schema:
{{
  "Candidate_1": {{
    "saif_owasp_mapping": <int 1-5>,
    "technical_depth_and_accuracy": <int 1-5>,
    "cloud_to_code_drift_and_visibility": <int 1-5>,
    "remediation_executability": <int 1-5>,
    "signal_to_noise_and_structure": <int 1-5>,
    "rationale": "<concise justification>"
  }},
  "Candidate_2": {{
    "saif_owasp_mapping": <int 1-5>,
    "technical_depth_and_accuracy": <int 1-5>,
    "cloud_to_code_drift_and_visibility": <int 1-5>,
    "remediation_executability": <int 1-5>,
    "signal_to_noise_and_structure": <int 1-5>,
    "rationale": "<concise justification>"
  }},
  "overall_winner": "<Candidate_1 or Candidate_2 or Tie>",
  "comparison_summary": "<2-3 sentence executive comparison explaining why one report outperformed the other>"
}}
"""
    raw_resp = call_gemini(
        prompt=judge_prompt,
        system_instruction=judge_system,
        model=model,
        temperature=0.0,
        project_id=project_id,
    )

    m = re.search(r"\{.*\}", raw_resp, re.DOTALL)
    parsed = json.loads(m.group(0)) if m else {}

    def _to_rubric(d: dict[str, Any]) -> JudgeRubricScore:
        return JudgeRubricScore(
            saif_owasp_mapping=int(d.get("saif_owasp_mapping", 0)),
            technical_depth_and_accuracy=int(d.get("technical_depth_and_accuracy", 0)),
            cloud_to_code_drift_and_visibility=int(d.get("cloud_to_code_drift_and_visibility", 0)),
            remediation_executability=int(d.get("remediation_executability", 0)),
            signal_to_noise_and_structure=int(d.get("signal_to_noise_and_structure", 0)),
            rationale=str(d.get("rationale", "")),
        )

    c1_score = _to_rubric(parsed.get("Candidate_1", {}))
    c2_score = _to_rubric(parsed.get("Candidate_2", {}))
    summary = str(parsed.get("comparison_summary", ""))

    # Unblind back to (baseline_score, skill_score)
    if swap:
        return c2_score, c1_score, summary
    return c1_score, c2_score, summary


# ---------------------------------------------------------------------------
# Benchmark Runners (Fixtures or Live GCP Project)
# ---------------------------------------------------------------------------
def build_benchmark_context(gcp_project: str | None = None) -> tuple[str, str, list[GroundTruthItem]]:
    """Build (raw_context_for_baseline, skill_enriched_context, ground_truth_items)."""
    from fast_scan import SAIFScanner, format_markdown_summary
    from gcp_scan import GCPProjectScanner, format_gcp_markdown_report

    if gcp_project:
        gcp_scanner = GCPProjectScanner(project_id=gcp_project)
        gcp_res = gcp_scanner.scan()
        gcp_md = format_gcp_markdown_report(gcp_res)

        # Build dynamic ground truth from deterministic GCP findings discovered in the live project
        gt_items: list[GroundTruthItem] = []
        for f in gcp_scanner.findings:
            loc_str = f.location.split("/")[-1] if "/" in f.location else f.location
            kw_list = [w.lower() for w in re.findall(r"[A-Za-z0-9_-]{4,}", f.title)][:4]
            if not kw_list:
                kw_list = [f.saif_pillar.split(":")[0].lower()]
            gt_items.append(
                GroundTruthItem(
                    rule_id=f.rule_id,
                    description=f"{f.title}: {f.description}",
                    required_resource_or_file=loc_str,
                    concept_keywords=kw_list,
                )
            )

        # Raw baseline gets the raw GCP project ID, Cloud Asset Inventory resources, and IAM bindings
        raw_assets_json = json.dumps(gcp_scanner.compressed_resources[:30], indent=2)
        raw_iam_json = json.dumps(gcp_scanner.raw_iam_policies[:15], indent=2)
        baseline_ctx = (
            f"Live GCP Project ID: {gcp_project}\n\n"
            f"Discovered Cloud Asset Inventory Resources ({len(gcp_scanner.raw_resources)} total):\n"
            f"```json\n{raw_assets_json[:12000]}\n```\n\n"
            f"Discovered Cloud IAM Policies:\n"
            f"```json\n{raw_iam_json[:8000]}\n```\n"
        )
        skill_ctx = (
            f"### Step 1: Deterministic Live GCP Pre-Scan (`gcp_scan.py --project {gcp_project}`)\n"
            f"{gcp_md}\n\n"
            f"### Discovered Cloud Assets & IAM Context\n{baseline_ctx}"
        )
        return baseline_ctx, skill_ctx, gt_items

    # Default: Fixture Benchmark Mode (Mock GCP Project + Local Terraform/Python Fixtures)
    mock_assets = json.loads((FIXTURES_DIR / "mock_gcp_assets.json").read_text(encoding="utf-8"))
    mock_iam = json.loads((FIXTURES_DIR / "mock_iam_policies.json").read_text(encoding="utf-8"))

    gcp_scanner = GCPProjectScanner(
        project_id="mock-ai-prod-project",
        mock_assets_path=str(FIXTURES_DIR / "mock_gcp_assets.json"),
        mock_iam_path=str(FIXTURES_DIR / "mock_iam_policies.json"),
    )
    gcp_res = gcp_scanner.scan()
    gcp_md = format_gcp_markdown_report(gcp_res)

    local_scanner = SAIFScanner(FIXTURES_DIR)
    local_findings = local_scanner.scan()
    local_md = format_markdown_summary(local_findings)

    tf_code = (FIXTURES_DIR / "terraform" / "storage_no_cmek.tf").read_text(encoding="utf-8")
    py_rag = (FIXTURES_DIR / "python" / "unfiltered_vector_search.py").read_text(encoding="utf-8")
    py_loop = (FIXTURES_DIR / "python" / "infinite_agent_loop.py").read_text(encoding="utf-8")

    baseline_ctx = (
        "GCP Project ID: mock-ai-prod-project\n\n"
        f"Cloud Assets JSON:\n```json\n{json.dumps(mock_assets, indent=2)}\n```\n\n"
        f"IAM Policy JSON:\n```json\n{json.dumps(mock_iam, indent=2)}\n```\n\n"
        f"Local File `tests/fixtures/terraform/storage_no_cmek.tf`:\n```hcl\n{tf_code}\n```\n\n"
        f"Local File `tests/fixtures/python/unfiltered_vector_search.py`:\n```python\n{py_rag}\n```\n\n"
        f"Local File `tests/fixtures/python/infinite_agent_loop.py`:\n```python\n{py_loop}\n```\n"
    )

    skill_ctx = (
        f"### Step 1A: Deterministic GCP Pre-Scan (`gcp_scan.py`)\n{gcp_md}\n\n"
        f"### Step 1B: Deterministic Local Code/IaC Pre-Scan (`fast_scan.py`)\n{local_md}\n\n"
        f"### Source Files\n{baseline_ctx}"
    )
    return baseline_ctx, skill_ctx, FIXTURE_GROUND_TRUTH


def generate_scorecard_markdown(
    det_base: DeterministicScore,
    det_skill: DeterministicScore,
    judge_base: JudgeRubricScore,
    judge_skill: JudgeRubricScore,
    judge_summary: str,
    model: str,
    scope_label: str,
) -> str:
    """Format the A/B comparison scorecard as a GitHub-flavored Markdown report."""
    comp_base = round((det_base.total_deterministic_score * 0.5) + (judge_base.normalized_pct * 0.5), 1)
    comp_skill = round((det_skill.total_deterministic_score * 0.5) + (judge_skill.normalized_pct * 0.5), 1)
    delta = round(comp_skill - comp_base, 1)
    sign = "+" if delta >= 0 else ""

    return f"""# 🧪 SAIFGuard Skill vs. Baseline Gemini — A/B Benchmark Scorecard

* **Evaluated Scope**: `{scope_label}`
* **Model Tier**: `{model}`
* **Evaluation Methodology**: Hybrid 50% Deterministic Ground-Truth Scorer + 50% Blinded Pairwise LLM-as-a-Judge

---

## 🏆 Executive Summary Score

| Metric | Baseline Gemini (No Skill) | Gemini + SAIFGuard Skill | Delta |
| :--- | :---: | :---: | :---: |
| **Composite Benchmark Score (0–100)** | **{comp_base}%** | **{comp_skill}%** | **{sign}{delta}%** |
| **Layer 1: Deterministic Ground-Truth Score** | {det_base.total_deterministic_score}% | {det_skill.total_deterministic_score}% | {"+" if det_skill.total_deterministic_score >= det_base.total_deterministic_score else ""}{round(det_skill.total_deterministic_score - det_base.total_deterministic_score, 1)}% |
| **Layer 2: Blinded LLM-as-a-Judge Score** | {judge_base.normalized_pct}% | {judge_skill.normalized_pct}% | {"+" if judge_skill.normalized_pct >= judge_base.normalized_pct else ""}{round(judge_skill.normalized_pct - judge_base.normalized_pct, 1)}% |

> **Blinded Judge Verdict**: {judge_summary}

---

## 📊 Layer 1: Deterministic Ground-Truth Breakdown (Objective)

| Objective Check | Baseline Gemini | Gemini + SAIFGuard Skill |
| :--- | :---: | :---: |
| **Ground-Truth Vulnerability Recall** | `{det_base.recall_pct}%` ({len(det_base.matched_rules)}/{len(det_base.matched_rules) + len(det_base.missed_rules)}) | **`{det_skill.recall_pct}%` ({len(det_skill.matched_rules)}/{len(det_skill.matched_rules) + len(det_skill.missed_rules)})** |
| **GA `gcloud` Command Hygiene (Zero `alpha`/`beta`)** | `{det_base.ga_command_hygiene_pct}%` ({len(det_base.alpha_beta_violations)} violations) | **`{det_skill.ga_command_hygiene_pct}%` ({len(det_skill.alpha_beta_violations)} violations)** |
| **Clickable Console / File URI Grounding** | `{det_base.evidence_grounding_pct}%` | **`{det_skill.evidence_grounding_pct}%`** |
| **Cloud-to-Code Drift & API Visibility Matrix** | `{det_base.drift_and_visibility_pct}%` | **`{det_skill.drift_and_visibility_pct}%`** |
| **Missed Ground-Truth Rules** | `{", ".join(det_base.missed_rules) if det_base.missed_rules else "None"}` | `{", ".join(det_skill.missed_rules) if det_skill.missed_rules else "None"}` |

---

## ⚖️ Layer 2: Blinded Pairwise LLM-as-a-Judge Rubric (1–5 Scale)

| Rubric Dimension | Baseline Gemini | Gemini + SAIFGuard Skill |
| :--- | :---: | :---: |
| **1. SAIF Pillar (1–6) & OWASP LLM Mapping** | `{judge_base.saif_owasp_mapping} / 5` | **`{judge_skill.saif_owasp_mapping} / 5`** |
| **2. Technical Depth & Vulnerability Accuracy** | `{judge_base.technical_depth_and_accuracy} / 5` | **`{judge_skill.technical_depth_and_accuracy} / 5`** |
| **3. Cloud-to-Code Drift & Visibility Gap Analysis** | `{judge_base.cloud_to_code_drift_and_visibility} / 5` | **`{judge_skill.cloud_to_code_drift_and_visibility} / 5`** |
| **4. Remediation Copy-Paste Executability (GA `gcloud` / Diff)** | `{judge_base.remediation_executability} / 5` | **`{judge_skill.remediation_executability} / 5`** |
| **5. Signal-to-Noise Ratio & Severity Prioritization** | `{judge_base.signal_to_noise_and_structure} / 5` | **`{judge_skill.signal_to_noise_and_structure} / 5`** |
| **Judge Rationale** | *{judge_base.rationale}* | *{judge_skill.rationale}* |
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SAIFGuard Skill vs. Baseline Gemini A/B Evaluation.")
    parser.add_argument("--gcp-project", help="Optional live GCP project ID to benchmark (default: offline fixture suite)")
    parser.add_argument("--model", default="gemini-3.8-flash", help="Gemini model to use (default: gemini-3.8-flash)")
    parser.add_argument("--output", "-o", default="", help="Optional path to save the Markdown scorecard")
    parser.add_argument(
        "--output-dir",
        default="",
        help="Optional directory to save baseline_report.md, saifguard_skill_report.md, and benchmark_scorecard.md",
    )
    args = parser.parse_args()

    scope_label = f"Live GCP Project: {args.gcp_project}" if args.gcp_project else "Fixture Suite (Mock GCP + Terraform + Python)"
    print(f"🔍 Building benchmark context for: {scope_label}...")
    baseline_ctx, skill_ctx, ground_truth = build_benchmark_context(args.gcp_project)

    # 1. Run Baseline Gemini (Without Skill)
    print(f"🤖 [1/3] Running Baseline Gemini ({args.model}) WITHOUT SAIFGuard skill...")
    baseline_prompt = (
        "Analyze the security posture of this GCP project and codebase according to Google's Secure AI Framework (SAIF) "
        "and OWASP Top 10 for LLMs. Provide a comprehensive security audit report with findings and remediation steps.\n\n"
        f"{baseline_ctx}"
    )
    baseline_report = call_gemini(
        prompt=baseline_prompt,
        system_instruction="You are a helpful cloud security assistant.",
        model=args.model,
        project_id=args.gcp_project,
    )

    # 2. Run Gemini WITH SAIFGuard Skill
    print(f"🛡️  [2/3] Running Gemini ({args.model}) WITH SAIFGuard Skill (Step 1 Scanners + Step 2 References + Template)...")
    skill_system_parts = [
        (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8"),
        (REFS_DIR / "saif_gcp_live_audit.md").read_text(encoding="utf-8"),
        (REFS_DIR / "saif_pillar_1_foundations_iac.md").read_text(encoding="utf-8"),
        (REFS_DIR / "saif_pillar_3_automated_rag.md").read_text(encoding="utf-8"),
        (REFS_DIR / "saif_pillar_4_agents_cicd.md").read_text(encoding="utf-8"),
        (RESOURCES_DIR / "report_template.md").read_text(encoding="utf-8"),
    ]
    skill_prompt = (
        "Produce the complete SAIF_AUDIT_REPORT.md following `resources/report_template.md`. "
        "Include every deterministic finding from Step 1, explicitly identify Cloud-to-Code Shadow AI drift and API visibility gaps, "
        "cite clickable `https://console.cloud.google.com/...` and `file:///...` links, and use strictly GA `gcloud` commands.\n\n"
        f"{skill_ctx}"
    )
    skill_report = call_gemini(
        prompt=skill_prompt,
        system_instruction="\n\n---\n\n".join(skill_system_parts),
        model=args.model,
        project_id=args.gcp_project,
    )

    # 3. Evaluate Both Reports (Layer 1 Deterministic + Layer 2 Blinded Judge)
    print("⚖️  [3/3] Running Layer 1 Deterministic Scorer & Layer 2 Blinded Pairwise LLM-as-a-Judge...")
    det_base = score_report_deterministically(baseline_report, ground_truth)
    det_skill = score_report_deterministically(skill_report, ground_truth)
    judge_base, judge_skill, judge_summary = run_blinded_llm_judge(
        baseline_report=baseline_report,
        skill_report=skill_report,
        target_summary=baseline_ctx,
        model=args.model,
        project_id=args.gcp_project,
    )

    scorecard = generate_scorecard_markdown(
        det_base=det_base,
        det_skill=det_skill,
        judge_base=judge_base,
        judge_skill=judge_skill,
        judge_summary=judge_summary,
        model=args.model,
        scope_label=scope_label,
    )

    print("\n" + scorecard)
    if args.output:
        Path(args.output).write_text(scorecard, encoding="utf-8")
        print(f"✓ Saved benchmark scorecard to: {args.output}")
    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        base_file = out_dir / "baseline_report.md"
        skill_file = out_dir / "saifguard_skill_report.md"
        score_file = out_dir / "benchmark_scorecard.md"
        base_file.write_text(baseline_report, encoding="utf-8")
        skill_file.write_text(skill_report, encoding="utf-8")
        score_file.write_text(scorecard, encoding="utf-8")
        print(f"✓ Saved Baseline report to:   {base_file}")
        print(f"✓ Saved SAIFGuard report to:  {skill_file}")
        print(f"✓ Saved Benchmark scorecard:  {score_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
