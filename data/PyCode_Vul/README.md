# PyCode Vul: A Python Benchmark Dataset for Code-Level Vulnerability Detection and Analysis.

> A curated dataset of Python code snippets labeled for software vulnerability detection, suitable for research on ML/DL/LLM methods.

![License](https://img.shields.io/badge/License-CC%20BY%204.0-blue.svg)
![Task](https://img.shields.io/badge/task-vulnerability--detection-orange)
![Language](https://img.shields.io/badge/language-Python-brightgreen)

## ✨ Overview
**PyCode-Vul** contains labeled Python functions/snippets for vulnerability detection research. It supports **binary** (vulnerable vs. non-vulnerable) and **multi-label** settings (e.g., CWE categories).  
Use cases include supervised baselines, representation learning, prompt engineering for LLMs, and evaluation of explainability (e.g., vulnerable-line highlighting).

> **Version:** `<FILL_ME>` • **Total samples:** `<FILL_ME>` • **Vulnerable:** `<FILL_ME>` • **Non-vulnerable:** `<FILL_ME>`

## 📦 Data Sources & Construction (summary)
- Repos mined from `<FILL_ME: sources, e.g., GitHub projects / curated lists>`.
- Security-relevant commits identified via keywords/CVE/CWE tags and static-analysis signals.
- Functions/snippets extracted (AST/heuristics) and normalized.
- Labels derived from `<FILL_ME: commit messages, security tags, manual review, tools>`.
- Deduplication via normalized text hashing & near-duplicate filters.

A detailed methodology is in **docs/methodology.md** (add in repo if applicable).

## 🧾 Schema
Each row (CSV/JSONL) includes:
- `id` (str) — unique identifier  
- `repo`, `file_path`, `commit_sha` (str)  
- `function` or `code` (str) — Python code snippet  
- `label` (int) — 0 = non-vulnerable, 1 = vulnerable  
- `cwe_ids` (list|str) — e.g., `["CWE-79","CWE-89"]` (if available)  
- `vuln_type` (str) — normalized category (optional)  
- `split` (str) — `train`/`dev`/`test`  
- optional: `before_code`, `after_code`, `message`, `notes`

> Provide a small preview table in `data/README.md` with counts per split.

## 🧪 Tasks
- **Binary classification:** predict `label ∈ {0,1}`.  
- **Multi-label (optional):** predict CWE group(s) from `cwe_ids`.  
- **Explainability (optional):** highlight vulnerable lines/spans.

### Recommended Metrics
Accuracy, Precision/Recall/F1, **MCC**, AUROC, AUPRC; for multi-label: micro/macro F1.


