#!/usr/bin/env python3
"""SAIFGuard Python CLI.

Provides unified IDE skill installation, deterministic scanning (local code & live GCP projects),
and Gemini-powered SAIF security auditing.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

VERSION = "0.2.0"


def get_canonical_skill_dir() -> Path:
    """Resolve the canonical saifguard skill source directory."""
    return Path(__file__).resolve().parent / "skills" / "saifguard"


def copy_skill_tree(src: Path, dest: Path) -> None:
    """Copy the skill tree as real physical files (replacing any symlink)."""
    if dest.is_symlink():
        dest.unlink()
    dest.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        if item.name == "__pycache__":
            continue
        target = dest / item.name
        if target.is_symlink():
            target.unlink()
        if item.is_dir():
            shutil.copytree(
                item,
                target,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        elif item.is_file():
            shutil.copy2(item, target)


def cmd_init(args: argparse.Namespace) -> int:
    source_dir = get_canonical_skill_dir()
    if not source_dir.is_dir():
        print(f"Error: Canonical skill directory not found at {source_dir}", file=sys.stderr)
        return 1

    if args.global_install:
        global_target = Path.home() / ".gemini" / "config" / "skills" / "saifguard"
        print(f"Installing SAIFGuard skill globally to: {global_target}...")
        copy_skill_tree(source_dir, global_target)
        print("\n🎉 Successfully installed SAIFGuard globally!")
        print("Available across all your Antigravity / Jetski workspaces.")
        return 0

    target_dir = Path(args.target).expanduser().resolve() if getattr(args, "target", None) else Path.cwd()
    target_dir.mkdir(parents=True, exist_ok=True)
    print(f"Installing SAIFGuard skill into workspace: {target_dir}...")

    # 1. Antigravity / Jetski workspace path
    agents_target = target_dir / ".agents" / "skills" / "saifguard"
    copy_skill_tree(source_dir, agents_target)
    print("  ✓ Installed Antigravity/Jetski skill: .agents/skills/saifguard/")

    skill_md = source_dir / "SKILL.md"
    raw_skill_content = skill_md.read_text(encoding="utf-8") if skill_md.is_file() else ""
    resolved_skill_content = raw_skill_content.replace("<SKILL_DIR>", ".agents/skills/saifguard")

    # 2. Cursor detection
    if (target_dir / ".cursor").is_dir() or args.cursor:
        cursor_dir = target_dir / ".cursor" / "rules"
        cursor_dir.mkdir(parents=True, exist_ok=True)
        cursor_rule = f"---\ndescription: Google SAIF and OWASP LLM security auditor\nglobs: **/*\nalwaysApply: false\n---\n\n{resolved_skill_content}\n"
        (cursor_dir / "saifguard.mdc").write_text(cursor_rule, encoding="utf-8")
        print("  ✓ Generated Cursor rule: .cursor/rules/saifguard.mdc")

    # 3. Claude Code detection
    if (target_dir / ".claude").is_dir() or args.claude:
        claude_dir = target_dir / ".claude" / "commands"
        claude_dir.mkdir(parents=True, exist_ok=True)
        (claude_dir / "saifguard.md").write_text(resolved_skill_content, encoding="utf-8")
        print("  ✓ Generated Claude Code slash command: .claude/commands/saifguard.md")

    # 4. GitHub Copilot detection (idempotent update)
    if (target_dir / ".github").is_dir() or args.copilot:
        github_dir = target_dir / ".github"
        github_dir.mkdir(parents=True, exist_ok=True)
        copilot_file = github_dir / "copilot-instructions.md"
        existing = copilot_file.read_text(encoding="utf-8") if copilot_file.is_file() else ""
        marker = "## Google SAIF Security Guidelines"
        if marker not in existing:
            with open(copilot_file, "a", encoding="utf-8") as f:
                f.write(f"\n\n{marker}\n{resolved_skill_content}\n")
        print("  ✓ Configured GitHub Copilot instructions: .github/copilot-instructions.md")

    print("\n🎉 Successfully installed SAIFGuard!")
    print("Next steps:")
    print("  • Type '/saifguard' in your IDE chat to audit local files.")
    print("  • Type '/saifguard gcp <project_id>' to audit a live GCP project.")
    print("  • Run 'saifguard scan .' or 'saifguard scan --gcp-project <ID>' for deterministic scans.")
    print("  • Run 'saifguard audit .' or 'saifguard audit --gcp-project <ID>' for full LLM SAIF reports.")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    skill_dir = get_canonical_skill_dir()
    if not skill_dir.is_dir():
        skill_dir = Path.cwd() / ".agents" / "skills" / "saifguard"

    scan_target = getattr(args, "dir", None) or args.target or "."

    # GCP Project Scan Mode
    if args.gcp_project:
        gcp_script = skill_dir / "scripts" / "gcp_scan.py"
        if not gcp_script.is_file():
            print(f"Error: gcp_scan.py not found at {gcp_script}", file=sys.stderr)
            return 1
        cmd = [sys.executable, str(gcp_script), "--project", args.gcp_project, f"--format={args.format}"]
        if args.output:
            cmd.extend(["--output", args.output])
        if args.fail_on:
            cmd.append(f"--fail-on={args.fail_on}")
        if getattr(args, "mock_assets", None):
            cmd.extend(["--mock-assets", args.mock_assets])
        if getattr(args, "mock_iam", None):
            cmd.extend(["--mock-iam", args.mock_iam])
        result = subprocess.run(cmd)
        return result.returncode

    # Local Code Scan Mode
    fast_scan_script = skill_dir / "scripts" / "fast_scan.py"
    if not fast_scan_script.is_file():
        print(f"Error: fast_scan.py not found at {fast_scan_script}", file=sys.stderr)
        return 1

    cmd = [sys.executable, str(fast_scan_script), scan_target, f"--format={args.format}"]
    if args.output:
        cmd.extend(["--output", args.output])
    if args.fail_on:
        cmd.append(f"--fail-on={args.fail_on}")
    if args.ignore_file:
        cmd.append(f"--ignore-file={args.ignore_file}")
    if getattr(args, "tf_plan", None):
        cmd.extend(["--tf-plan", args.tf_plan])
    if getattr(args, "max_context_kb", None):
        cmd.append(f"--max-context-kb={args.max_context_kb}")

    result = subprocess.run(cmd)
    return result.returncode


def cmd_audit(args: argparse.Namespace) -> int:
    """Execute full hybrid (Deterministic + LLM) SAIF security audit."""
    output_file = args.output or "SAIF_AUDIT_REPORT.md"
    audit_target = getattr(args, "dir", None) or args.target or "."

    # Ensure src/ is importable if running directly from repo
    src_parent = Path(__file__).resolve().parent.parent
    if str(src_parent) not in sys.path:
        sys.path.insert(0, str(src_parent))

    if args.gcp_project:
        from saifguard.gcp_project_tool import gcp_project_tool

        print(f"🛡️  Running SAIFGuard Hybrid Audit on GCP Project '{args.gcp_project}'...")
        report = gcp_project_tool(
            gcp_project_id=args.gcp_project,
            local_repo_path=audit_target,
            output_path=output_file,
        )
        if report.startswith(("Error", "An exception occurred")):
            print(report, file=sys.stderr)
            return 1
        print(f"\n✓ Audit complete! Full report saved to: {output_file}")
        return 0

    from saifguard.analysis_tool import analysis_tool

    print(f"🛡️  Running SAIFGuard Hybrid Audit on target '{audit_target}'...")
    report = analysis_tool(
        target_uri_or_path=audit_target,
        output_path=output_file,
        max_context_kb=args.max_context_kb,
    )
    if report.startswith(("Error", "An exception occurred")):
        print(report, file=sys.stderr)
        return 1
    print(f"\n✓ Audit complete! Full report saved to: {output_file}")
    return 0


def cmd_install_hook(args: argparse.Namespace) -> int:
    git_dir = Path.cwd() / ".git"
    if not git_dir.is_dir():
        print("Error: No .git directory found. Run this command in a git repository root.", file=sys.stderr)
        return 1

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    pre_commit = hooks_dir / "pre-commit"

    script = """#!/bin/sh
# SAIFGuard Git Pre-Commit Hook
# Prevents committing Critical or High SAIF/OWASP AI security violations.

echo "🛡️  Running SAIFGuard pre-commit security scan..."
for SCANNER in ".agents/skills/saifguard/scripts/fast_scan.py" "src/saifguard/skills/saifguard/scripts/fast_scan.py" "$HOME/.gemini/config/skills/saifguard/scripts/fast_scan.py"; do
    if [ -f "$SCANNER" ]; then
        python3 "$SCANNER" . --fail-on=HIGH --format=summary
        STATUS=$?
        if [ $STATUS -ne 0 ]; then
            echo "❌ SAIFGuard pre-commit scan failed. Fix the Critical/High issues above or add '# saifguard:ignore' before committing."
            exit 1
        fi
        exit 0
    fi
done
exit 0
"""
    pre_commit.write_text(script, encoding="utf-8")
    pre_commit.chmod(0o755)
    print("✓ Installed git pre-commit hook: .git/hooks/pre-commit")
    print("Commits with Critical or High SAIF violations will be blocked.")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    print(f"SAIFGuard Version: {VERSION}\n")
    print("Installed custom skills:")
    checks = [
        ("Workspace Antigravity/Jetski", Path.cwd() / ".agents" / "skills" / "saifguard" / "SKILL.md"),
        ("Workspace Cursor Rule", Path.cwd() / ".cursor" / "rules" / "saifguard.mdc"),
        ("Workspace Claude Command", Path.cwd() / ".claude" / "commands" / "saifguard.md"),
        ("Global Jetski Skill", Path.home() / ".gemini" / "config" / "skills" / "saifguard" / "SKILL.md"),
    ]
    for label, p in checks:
        status = "✅ Installed" if p.is_file() else "❌ Not installed"
        print(f"  • {label}: {status} ({p})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=f"SAIFGuard CLI v{VERSION} - Google SAIF & OWASP AI Security Auditor")
    parser.add_argument("-v", "--version", action="version", version=f"saifguard v{VERSION}")
    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # init
    p_init = subparsers.add_parser("init", help="Install SAIFGuard skill into workspace or globally")
    p_init.add_argument("target_pos", nargs="?", default=None, help="Optional target workspace directory")
    p_init.add_argument("--target", "--dir", dest="target", default=None, help="Target workspace directory to install the skill into (default: current directory)")
    p_init.add_argument("--global", dest="global_install", action="store_true", help="Install globally into ~/.gemini/config/skills/saifguard")
    p_init.add_argument("--cursor", action="store_true", help="Force generate Cursor .mdc rule")
    p_init.add_argument("--claude", action="store_true", help="Force generate Claude Code command")
    p_init.add_argument("--copilot", action="store_true", help="Force append to Copilot instructions")

    # scan
    p_scan = subparsers.add_parser("scan", help="Run deterministic security pre-scan (local files or live GCP project)")
    p_scan.add_argument("target", nargs="?", default=".", help="Target directory (default: .)")
    p_scan.add_argument("--dir", "--target", dest="dir", default=None, help="Target directory or file path")
    p_scan.add_argument("--gcp-project", default=None, help="Target GCP Project ID to scan via Cloud Asset Inventory")
    p_scan.add_argument("--format", choices=["markdown", "json", "sarif", "summary"], default="markdown")
    p_scan.add_argument("--output", default=None, help="Write report output to file (e.g. SAIF_AUDIT_REPORT.md)")
    p_scan.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None)
    p_scan.add_argument("--ignore-file", default=None)
    p_scan.add_argument("--tf-plan", default=None, help="Optional terraform show -json plan file")
    p_scan.add_argument("--max-context-kb", type=int, default=120, help="Context budget ceiling in KB")
    p_scan.add_argument("--mock-assets", default=None, help="Mock GCP assets fixture path (for testing)")
    p_scan.add_argument("--mock-iam", default=None, help="Mock GCP IAM fixture path (for testing)")

    # audit
    p_audit = subparsers.add_parser("audit", help="Run full hybrid (Deterministic + LLM) SAIF security audit")
    p_audit.add_argument("target", nargs="?", default=".", help="Target local path, PDF, Google Docs URL, or gs:// URI (default: .)")
    p_audit.add_argument("--dir", "--target", dest="dir", default=None, help="Target local path, PDF, Google Docs URL, or gs:// URI")
    p_audit.add_argument("--gcp-project", default=None, help="Target GCP Project ID to audit")
    p_audit.add_argument("--output", default="SAIF_AUDIT_REPORT.md", help="Output Markdown report filename")
    p_audit.add_argument("--max-context-kb", type=int, default=120, help="Context budget ceiling in KB")

    # install-hook
    subparsers.add_parser("install-hook", help="Install git pre-commit hook")

    # list
    subparsers.add_parser("list", help="List active installations")

    args = parser.parse_args()
    if not args.command or args.command == "help":
        parser.print_help()
        return 0

    if args.command == "init":
        if not args.target and getattr(args, "target_pos", None):
            args.target = args.target_pos
        return cmd_init(args)
    elif args.command == "scan":
        return cmd_scan(args)
    elif args.command == "audit":
        return cmd_audit(args)
    elif args.command == "install-hook":
        return cmd_install_hook(args)
    elif args.command == "list":
        return cmd_list(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
