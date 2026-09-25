"""Unit tests for the SAIFGuard A/B Evaluation & Scorer suite (tests/eval/eval_skill_vs_baseline.py)."""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.eval.eval_skill_vs_baseline import (
    FIXTURE_GROUND_TRUTH,
    JudgeRubricScore,
    generate_scorecard_markdown,
    score_report_deterministically,
)


class TestEvalScorer(unittest.TestCase):
    def test_deterministic_scorer_distinguishes_skill_from_baseline(self):
        baseline_sample = (
            "# General Security Review\n"
            "You should consider using CMEK and IAM best practices.\n"
            "Run `gcloud alpha ai endpoints update 1234567890` to configure KMS.\n"
        )
        skill_sample = (
            "# 🛡️ SAIF Security & Architecture Audit Report\n"
            "## Audit Coverage & API Visibility\n"
            "- Cloud Asset Inventory: Scanned\n"
            "- Cloud-to-Code Drift: Shadow AI / ClickOps endpoint `987654321` missing from `storage_no_cmek.tf`.\n\n"
            "### 1. [🔴 Critical] `GCP_SAIF_VERTEX_ENDPOINT_NO_CMEK` — Missing CMEK on Vertex Endpoint\n"
            "* **SAIF Pillar**: Pillar 1: Strong Foundations | **OWASP LLM**: LLM06\n"
            "* **Location**: [Vertex Endpoint 987654321](https://console.cloud.google.com/vertex-ai/endpoints)\n"
            "EncryptionSpec kmsKeyName is missing.\n"
            "### 2. [🔴 Critical] `GCP_SAIF_STORAGE_NO_CMEK_OR_PUBLIC`\n"
            "`vertex-rag-embeddings-prod` lacks CMEK kms encryption.\n"
            "### 3. [🔴 Critical] `GCP_SAIF_LB_NO_CLOUD_ARMOR`\n"
            "`ai-gateway-backend` lacks Cloud Armor WAF securityPolicy.\n"
            "### 4. [🟠 High] `GCP_SAIF_SA_USER_MANAGED_KEY`\n"
            "`sa@gcp-project.iam.gserviceaccount.com` uses static USER_MANAGED key instead of Workload Identity.\n"
            "### 5. [🟠 High] `GCP_SAIF_MODEL_ARMOR_NOT_CONFIGURED`\n"
            "No Model Armor guardrail floorSettings configured.\n"
            "### 6. [🔴 Critical] `SAIF_PILLAR3_RAG_UNFILTERED_SEARCH`\n"
            "[unfiltered_vector_search.py](file:///app/unfiltered_vector_search.py#L12) calls `similarity_search` without tenant `filter`.\n"
            "### 7. [🟠 High] `SAIF_PILLAR4_AGENT_INFINITE_LOOP`\n"
            "[infinite_agent_loop.py](file:///app/infinite_agent_loop.py#L8) has `while True` loop without `max_iterations`.\n"
            "```bash\n"
            "gcloud storage buckets update gs://vertex-rag-embeddings-prod --default-encryption-key=projects/p/locations/l/keyRings/r/cryptoKeys/k\n"
            "```\n"
        )

        det_base = score_report_deterministically(baseline_sample, FIXTURE_GROUND_TRUTH)
        det_skill = score_report_deterministically(skill_sample, FIXTURE_GROUND_TRUTH)

        self.assertEqual(det_skill.recall_pct, 100.0)
        self.assertEqual(det_skill.ga_command_hygiene_pct, 100.0)
        self.assertGreater(det_skill.total_deterministic_score, 95.0)

        self.assertLess(det_base.recall_pct, 30.0)
        self.assertEqual(len(det_base.alpha_beta_violations), 1)
        self.assertLess(det_base.total_deterministic_score, det_skill.total_deterministic_score)

        scorecard = generate_scorecard_markdown(
            det_base=det_base,
            det_skill=det_skill,
            judge_base=JudgeRubricScore(2, 2, 1, 2, 2, "Baseline missed key findings."),
            judge_skill=JudgeRubricScore(5, 5, 5, 5, 5, "Skill detected all SAIF findings and drift."),
            judge_summary="SAIFGuard Skill significantly outperformed Baseline Gemini.",
            model="gemini-2.5-flash",
            scope_label="Unit Test Suite",
        )
        self.assertIn("Composite Benchmark Score", scorecard)
        self.assertIn("100.0%", scorecard)


if __name__ == "__main__":
    unittest.main()
