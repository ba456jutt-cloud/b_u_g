# Architecture: Bug Bounty Copilot Phase 2

## Overview
The Phase 2 architecture builds upon the core engine to introduce specialized, defensive security agents. The system utilizes a router to dispatch tasks to the appropriate expert agent, which then processes the data, saves findings to the SQLite memory, and returns the analysis to the user.

## Component Flow
1. **User Input**: The user provides a task (e.g., "Review this code for vulnerabilities").
2. **TaskRouter**: Analyzes keywords in the task and selects the appropriate agent (e.g., `CodeReviewAgent`).
3. **Specialized Agent**: 
    - Formats a prompt specific to its domain (e.g., SAST analysis).
    - Optionally invokes `Tools` (e.g., `ReadFileTool`) to gather more context.
    - Interacts with the `LLMProvider` to generate insights.
    - Strict formatting constraints (like JSON output for `VulnerabilityAnalysisAgent`) are enforced during generation.
4. **Memory Integration**: The agent saves the parsed finding directly into the `key_findings` table via `MemoryDB`.
5. **Output**: The formatted result is returned to the user.

## Specialized Agents Built
- **ReconAnalysisAgent**: Parses recon data (Nmap, JSON) to summarize technologies and endpoints.
- **CVEResearchAgent**: Researches CVEs and maps to mitigations.
- **CodeReviewAgent**: Conducts defensive source code review (SAST).
- **SecurityKnowledgeAgent**: Answers questions on OWASP, CWE, and best practices.
- **VulnerabilityAnalysisAgent**: Generates strict JSON outputs detailing severity and business impact.
- **ReportAgent**: Compiles findings into executive summaries and Markdown reports.

*Note: All agents strictly adhere to defensive security rules and will not automate attacks.*
