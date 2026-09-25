#!/usr/bin/env node

/**
 * SAIFGuard CLI - Google SAIF & OWASP AI Security IDE Skill Installer & Scanner
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const VERSION = '0.2.0';

function getSkillSourceDir() {
  const candidate = path.resolve(__dirname, '../../src/saifguard/skills/saifguard');
  if (fs.existsSync(candidate)) {
    return candidate;
  }
  const bundled = path.resolve(__dirname, '../skills/saifguard');
  if (fs.existsSync(bundled)) {
    return bundled;
  }
  return candidate;
}

function copyDirRecursive(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirRecursive(srcPath, destPath);
    } else if (entry.isFile()) {
      fs.copyFileSync(srcPath, destPath);
      if (entry.name.endsWith('.py') || entry.name.endsWith('.sh')) {
        try {
          fs.chmodSync(destPath, 0o755);
        } catch (_) {}
      }
    }
  }
}

function generateCursorRule(skillDir, targetDir) {
  const skillFile = path.join(skillDir, 'SKILL.md');
  if (!fs.existsSync(skillFile)) return;
  const content = fs.readFileSync(skillFile, 'utf8');

  const cursorDir = path.join(targetDir, '.cursor', 'rules');
  fs.mkdirSync(cursorDir, { recursive: true });

  const mdcContent = `---
description: Google SAIF and OWASP LLM security auditor
globs: **/*
alwaysApply: false
---

${content}
`;
  fs.writeFileSync(path.join(cursorDir, 'saifguard.mdc'), mdcContent, 'utf8');
  console.log(`  ✓ Generated Cursor rule: .cursor/rules/saifguard.mdc`);
}

function generateClaudeCommand(skillDir, targetDir) {
  const skillFile = path.join(skillDir, 'SKILL.md');
  if (!fs.existsSync(skillFile)) return;
  const content = fs.readFileSync(skillFile, 'utf8');

  const claudeDir = path.join(targetDir, '.claude', 'commands');
  fs.mkdirSync(claudeDir, { recursive: true });

  fs.writeFileSync(path.join(claudeDir, 'saifguard.md'), content, 'utf8');
  console.log(`  ✓ Generated Claude Code slash command: .claude/commands/saifguard.md`);
}

function generateCopilotInstructions(skillDir, targetDir) {
  const skillFile = path.join(skillDir, 'SKILL.md');
  if (!fs.existsSync(skillFile)) return;
  const content = fs.readFileSync(skillFile, 'utf8');

  const githubDir = path.join(targetDir, '.github');
  fs.mkdirSync(githubDir, { recursive: true });

  const copilotFile = path.join(githubDir, 'copilot-instructions.md');
  const section = `\n\n## Google SAIF Security Guidelines\nWhen auditing or reviewing code for security, enforce the following SAIF rules:\n${content}\n`;
  fs.appendFileSync(copilotFile, section, 'utf8');
  console.log(`  ✓ Appended to GitHub Copilot instructions: .github/copilot-instructions.md`);
}

function initCommand(args) {
  const isGlobal = args.includes('--global');
  const sourceDir = getSkillSourceDir();

  if (!fs.existsSync(sourceDir)) {
    console.error(`Error: Canonical skill directory not found at ${sourceDir}`);
    process.exit(1);
  }

  if (isGlobal) {
    const globalTarget = path.join(os.homedir(), '.gemini', 'config', 'skills', 'saifguard');
    console.log(`Installing SAIFGuard skill globally to: ${globalTarget}...`);
    copyDirRecursive(sourceDir, globalTarget);
    console.log(`\n🎉 Successfully installed SAIFGuard globally!`);
    console.log(`Available across all your Antigravity / Jetski workspaces.`);
    return;
  }

  const targetDir = process.cwd();
  console.log(`Installing SAIFGuard skill into workspace: ${targetDir}...`);

  const agentsTarget = path.join(targetDir, '.agents', 'skills', 'saifguard');
  copyDirRecursive(sourceDir, agentsTarget);
  console.log(`  ✓ Installed Antigravity/Jetski skill: .agents/skills/saifguard/`);

  if (fs.existsSync(path.join(targetDir, '.cursor')) || args.includes('--cursor')) {
    generateCursorRule(sourceDir, targetDir);
  }

  if (fs.existsSync(path.join(targetDir, '.claude')) || args.includes('--claude')) {
    generateClaudeCommand(sourceDir, targetDir);
  }

  if (fs.existsSync(path.join(targetDir, '.github')) || args.includes('--copilot')) {
    generateCopilotInstructions(sourceDir, targetDir);
  }

  console.log(`\n🎉 Successfully installed SAIFGuard!`);
  console.log(`Next steps:`);
  console.log(`  • Type '/saifguard' in your IDE chat to start a local audit.`);
  console.log(`  • Type '/saifguard gcp <project_id>' to audit a live GCP project.`);
  console.log(`  • Run 'npx saifguard scan .' or 'npx saifguard scan --gcp-project <ID>'.`);
  console.log(`  • Run 'npx saifguard install-hook' to set up a git pre-commit security gate.`);
}

function scanCommand(args) {
  let gcpProject = null;
  const filteredArgs = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--gcp-project' && i + 1 < args.length) {
      gcpProject = args[i + 1];
      i++;
    } else if (args[i].startsWith('--gcp-project=')) {
      gcpProject = args[i].split('=', 2)[1];
    } else {
      filteredArgs.push(args[i]);
    }
  }

  if (gcpProject) {
    const gcpScriptPath = path.join(getSkillSourceDir(), 'scripts', 'gcp_scan.py');
    if (!fs.existsSync(gcpScriptPath)) {
      console.error(`Error: GCP scanner script not found at ${gcpScriptPath}`);
      process.exit(1);
    }
    const passArgs = [gcpScriptPath, '--project', gcpProject, ...filteredArgs.filter(a => a !== '.')];
    const proc = spawnSync('python3', passArgs, { stdio: 'inherit' });
    process.exit(proc.status !== null ? proc.status : 1);
  }

  const scriptPath = path.join(getSkillSourceDir(), 'scripts', 'fast_scan.py');
  if (!fs.existsSync(scriptPath)) {
    console.error(`Error: Scanner script not found at ${scriptPath}`);
    process.exit(1);
  }

  const passArgs = [scriptPath, ...args];
  const proc = spawnSync('python3', passArgs, { stdio: 'inherit' });
  process.exit(proc.status !== null ? proc.status : 1);
}

function auditCommand(args) {
  const cliPy = path.resolve(__dirname, '../../src/saifguard/cli.py');
  if (fs.existsSync(cliPy)) {
    const proc = spawnSync('python3', [cliPy, 'audit', ...args], { stdio: 'inherit' });
    process.exit(proc.status !== null ? proc.status : 1);
  }
  scanCommand(args);
}

function installHookCommand() {
  const gitDir = path.join(process.cwd(), '.git');
  if (!fs.existsSync(gitDir)) {
    console.error('Error: No .git directory found. Run this command in a git repository root.');
    process.exit(1);
  }

  const hooksDir = path.join(gitDir, 'hooks');
  fs.mkdirSync(hooksDir, { recursive: true });

  const hookFile = path.join(hooksDir, 'pre-commit');
  const hookScript = `#!/bin/sh
# SAIFGuard Git Pre-Commit Hook
# Prevents committing Critical or High SAIF/OWASP AI security violations.

echo "🛡️  Running SAIFGuard pre-commit security scan..."
python3 -c '
import sys
from pathlib import Path
for p in [Path(".agents/skills/saifguard/scripts/fast_scan.py"), Path("src/saifguard/skills/saifguard/scripts/fast_scan.py")]:
    if p.is_file():
        import subprocess
        res = subprocess.run([sys.executable, str(p), ".", "--fail-on=HIGH", "--format=summary"])
        sys.exit(res.returncode)
'
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "❌ SAIFGuard pre-commit scan failed. Fix the critical/high security issues above or add '# saifguard:ignore' before committing."
    exit 1
fi
exit 0
`;

  fs.writeFileSync(hookFile, hookScript, { encoding: 'utf8', mode: 0o755 });
  console.log(`✓ Installed git pre-commit hook: .git/hooks/pre-commit`);
  console.log(`Commits with Critical or High SAIF violations will be blocked.`);
}

function listCommand() {
  console.log(`SAIFGuard Version: ${VERSION}\n`);
  console.log(`Installed custom skills:`);

  const checks = [
    { label: 'Workspace Antigravity/Jetski', p: path.join(process.cwd(), '.agents', 'skills', 'saifguard', 'SKILL.md') },
    { label: 'Workspace Cursor Rule', p: path.join(process.cwd(), '.cursor', 'rules', 'saifguard.mdc') },
    { label: 'Workspace Claude Command', p: path.join(process.cwd(), '.claude', 'commands', 'saifguard.md') },
    { label: 'Global Jetski Skill', p: path.join(os.homedir(), '.gemini', 'config', 'skills', 'saifguard', 'SKILL.md') },
  ];

  for (const c of checks) {
    const status = fs.existsSync(c.p) ? '✅ Installed' : '❌ Not installed';
    console.log(`  • ${c.label}: ${status} (${c.p})`);
  }
}

function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'help';

  switch (command) {
    case 'init':
      initCommand(args.slice(1));
      break;
    case 'scan':
      scanCommand(args.slice(1));
      break;
    case 'audit':
      auditCommand(args.slice(1));
      break;
    case 'install-hook':
      installHookCommand();
      break;
    case 'list':
      listCommand();
      break;
    case '--version':
    case '-v':
      console.log(`saifguard v${VERSION}`);
      break;
    default:
      console.log(`SAIFGuard CLI v${VERSION} - Google SAIF & OWASP AI Security Auditor\n`);
      console.log(`Usage:`);
      console.log(`  npx saifguard init [--global] [--cursor] [--claude]     Install skill into workspace or globally`);
      console.log(`  npx saifguard scan [target] [--gcp-project ID]          Run deterministic security pre-scan`);
      console.log(`  npx saifguard audit [target] [--gcp-project ID]         Run full hybrid SAIF security audit`);
      console.log(`  npx saifguard install-hook                              Install git pre-commit security gate`);
      console.log(`  npx saifguard list                                      List active installations`);
      break;
  }
}

main();
