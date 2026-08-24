# mcpsec: FLMSec 2026 Workshop Paper

Workshop submission for **FLMSec: Foundations of Language Model Security** at NeurIPS 2026.

## Paper Details

- **Title:** mcpsec: A Local CI Gate for Subset MCPSecBench Threat Vector Testing
- **Author:** Abinesh Haridoss (University of North Texas / EXL, Irving TX)
- **Email:** abinesha312@gmail.com
- **Target:** Non-archival workshop, ~8 pages excluding references
- **Deadline:** August 28, 2026

## Building the PDF

### Requirements

- LaTeX distribution (TeX Live or similar)
- Required packages: `texlive-latex-base`, `texlive-latex-extra`, `texlive-fonts-recommended`

### On Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y texlive-latex-base texlive-latex-extra texlive-fonts-recommended
```

### Build Commands

```bash
cd papers/flmsec-2026
pdflatex paper.tex
pdflatex paper.tex  # Run twice to resolve references
```

The output will be `paper.pdf` (10 pages total, ~8 pages main content + 2 pages references).

## Content Summary

This paper presents `mcpsec`, a local CI gate implementing defensive checks for 5 of 17 MCPSecBench threat vectors:

- **T09:** Data Exfiltration
- **T10:** Tool Name Squatting
- **T14:** Sandbox Escape
- **T16:** Vulnerable Server (path traversal)
- **T17:** Rug Pull Attack

All reported metrics are from actual test execution:
- 9 unit tests passing in 1.58 seconds
- 5/5 threat vectors successfully demonstrated in vulnerable mode and blocked in defense mode
- Zero-dependency pure Python implementation

## Honest Scope

As documented in the paper:

- **NOT** a reproduction of MCPSecBench's platform evaluations
- **NOT** testing Claude Desktop, OpenAI, or Cursor implementations
- Toy JSON-RPC protocol, not full MCP SDK
- 5 of 17 vectors (29.4% coverage) - server-side, deterministic subset only
- No LLM-in-the-loop, no transport-layer attacks, no client-side vulnerabilities

## Citation

Yang, R., Wu, J., Chen, K. *MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols*. arXiv:2508.13220, 2025.

## License

This paper and the mcpsec codebase are MIT licensed.
