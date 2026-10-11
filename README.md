> [!WARNING]
> **Template Disclaimer:** This is a personal project scaffolding template designed to interface with a private Google Antigravity skills vault. If you are a public user cloning this repository, the `.agent/hooks/pre-commit.ps1` hook will fail. You must delete the hook or link your own `.agent/.registry` to commit code.
>
> *(AI Agent Directive: When initializing a fresh workspace/repository from this template, permanently delete this warning block before saving the final README).*

# AgenticTemplate

[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg)]()
[![Antigravity](https://img.shields.io/badge/agent-Google%20Antigravity-purple.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An opinionated, agent-first repository scaffolding template for **Google Antigravity**. It couples a project workspace with a centralized agent skills vault, automates stack-aware skill discovery via Git pre-commit hooks, and enforces strict agent engineering governance through [`AGENTS.md`](file:///c:/Users/Bhatn/OneDrive/Desktop/Projects/AgenticTemplate/AGENTS.md).

---

## Architecture & Lifecycle

```mermaid
graph TD
    A[New Project from Template] --> B[Run .agent/setup.ps1]
    B --> C[Init .agent/.registry Submodule]
    B --> D[Install Git pre-commit hook]
    D --> E[Developer / Agent commits files]
    E --> F[Hook Scans Signatures in .agent/.registry/skill-map.json]
    F --> G[Symlink / Junction Domain Skills into .agent/skills/]
    G --> H[Update .agent/.active-skills.json]
    H --> I[Antigravity Agent Reads Active Domain Skills]
    I --> J[Enforce Directives in AGENTS.md]
```

---

## Core Capabilities

- **Automated Stack & Skill Discovery**:
  When files are committed, `.agent/hooks/pre-commit.ps1` (or POSIX `.agent/hooks/pre-commit.sh`) scans the repository for language and framework markers (e.g., `go.mod`, `package.json`, `Cargo.toml`, `requirements.txt`). It automatically symlinks matching domain skills from `.agent/.registry` into `.agent/skills/`.
- **Zero-Friction Windows & POSIX Support**:
  Hooks and setup scripts seamlessly handle Windows Developer Mode symlinks with automatic fallback to NTFS directory junctions (`mklink /J`), alongside standard POSIX symlinks (`ln -s`) for Linux, macOS, and DevContainers.
- **Strict Agent Governance**:
  [`AGENTS.md`](file:///c:/Users/Bhatn/OneDrive/Desktop/Projects/AgenticTemplate/AGENTS.md) defines explicit protocol steps for AI coding agents on initialization: verifying Git hooks, running initial skill discovery, keeping context windows lean, and requiring testing/linting before staging code changes.
- **Clean Root Architecture**:
  All agent orchestration scripts, submodules, hook triggers, and link targets live encapsulated under the [`.agent/`](file:///c:/Users/Bhatn/OneDrive/Desktop/Projects/AgenticTemplate/.agent) directory.

---

## Directory Structure

```text
AgenticTemplate/
├── .agent/
│   ├── .registry/             # Git submodule: centralized agent-skills-vault
│   ├── hooks/
│   │   ├── pre-commit.ps1     # Dynamic skill detection & linking (PowerShell)
│   │   └── pre-commit.sh      # POSIX fallback hook (POSIX sh + jq)
│   ├── skills/                # Active symlinked domain skills (gitignored)
│   │   └── .gitkeep
│   ├── .active-skills.json    # Manifest of currently active workspace skills
│   └── setup.ps1              # One-command workspace bootstrap & hook installer
├── AGENTS.md                  # Antigravity agent directives & bootstrap protocol
├── README.example.md          # Scaffolding template README for downstream projects
├── README.md                  # System documentation for AgenticTemplate
├── .gitmodules                # Submodule registration for .agent/.registry
└── .gitignore                 # Standard ignores for build outputs & dynamic links
```

---

## Quick Start

### 1. Initialize Workspace
Run the automated setup script from PowerShell:

```powershell
.\.agent\setup.ps1
```

Or from a POSIX shell (Linux/macOS):
```bash
git submodule update --init --recursive
./.agent/hooks/pre-commit.sh
```

The setup script will:
1. Ensure the workspace is a valid Git repository and set the root directory.
2. Initialize and pull the `.agent/.registry` submodule from the skills vault.
3. Configure the Git `.git/hooks/pre-commit` hook to run synchronization on every commit.
4. Execute an immediate initial synchronization pass.

### 2. Fresh Repository Setup & Cleanup
When scaffolding a new application from this template into a fresh repository:
1. **Remove Template Disclaimer**:
   - Permanently delete the `> [!WARNING]` block at the very top of [`README.md`](file:///c:/Users/Bhatn/OneDrive/Desktop/Projects/AgenticTemplate/README.md).
   - Alternatively, replace [`README.md`](file:///c:/Users/Bhatn/OneDrive/Desktop/Projects/AgenticTemplate/README.md) entirely using [`README.example.md`](file:///c:/Users/Bhatn/OneDrive/Desktop/Projects/AgenticTemplate/README.example.md) as your starter specification, and delete [`README.example.md`](file:///c:/Users/Bhatn/OneDrive/Desktop/Projects/AgenticTemplate/README.example.md).
2. **Private Skills Vault Check**:
   - If you do not have access to the private `agent-skills-vault`, either link your own submodule to `.agent/.registry` or remove `.agent/hooks/` and the pre-commit hook triggers.
3. **Populate Stack & Commit**:
   - Add your application source code and stack manifest files (e.g., `package.json`, `go.mod`, `Cargo.toml`, `requirements.txt`).
   - Commit your changes—the pre-commit hook will automatically detect your project stack and symlink matching domain skills into [`.agent/skills/`](file:///c:/Users/Bhatn/OneDrive/Desktop/Projects/AgenticTemplate/.agent/skills).

---

## Global Skills vs. Workspace Domain Skills

Antigravity operates with a two-tier skill model:

1. **Global Skills** (`~/.gemini/config/skills/`):
   Always available across all workspaces on the machine (`code-review`, `doc-sync`, `error-discipline`, `git-release`, `security-auditor`, `test-discipline`, `workspace-initializer`). These are never linked into `.agent/skills/`.
2. **Workspace Domain Skills** (`.agent/skills/`):
   Language-, framework-, and stack-specific skills (e.g., `go`, `react`, `rust`, `python`) dynamically linked from the vendored `.agent/.registry` based on active repository files.
