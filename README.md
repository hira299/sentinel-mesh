# Sentinel-Mesh

> **Manuscript under review at IEEE Access Journal (Manuscript ID: Access-2026-19287)**

Neuro-symbolic framework for autonomous remediation of cloud infrastructure misconfigurations. Combines LLM-driven patch generation with Z3 SMT formal verification in a closed feedback loop.

---

### Technical Resources
For a detailed technical deep-dive into the Cloud Perimeter Model and the SMT logic used in this framework, read the article on Medium: 
**[Beyond Heuristics: Formally Verifying AI-Generated Infrastructure with Z3 SMT Solvers](https://medium.com/@hira229922/beyond-heuristics-formally-verifying-ai-generated-infrastructure-with-z3-smt-solvers-e95fd3a7bf95)**

---

## How it works

1. A Terraform misconfiguration is detected and passed to the LLM agent
2. The agent generates a remediation patch
3. The Z3 verifier checks the patch against formal security invariants (Cloud Perimeter Model)
4. If the patch fails verification, the Z3 error message is fed back to the LLM and the loop retries
5. Once the patch satisfies all invariants, it is accepted. For encryption and network violations, a formal proof certificate is additionally issued via dual-solver Z3 refinement (Solver A for Completeness, Solver B for Soundness) — 37/88 fixed cases in the benchmark received certificates

The verifier acts as a closed-loop acceptance oracle. The LLM cannot produce a patch that passes without satisfying the formal constraints.

---

## Benchmark results

Evaluated on 105 hand-crafted Terraform misconfiguration benchmark cases across 8 cloud infrastructure pillars.


&nbsp;

| Metric | Result |
|---|---|
| Overall remediation rate | 88/105 (83.81%) |
| One-shot resolution rate | 85.23% (75/88 at k=1) |
| Formal proof certificates issued | 37 (29 FPC + 8 PATCH REJECTED) |
| LLM hallucination rate | 16.19% (17/105) |
| Hallucinated patches blocked | 17/17 (0% regression rate) |
| Mean attempts per fixed case | μ=1.27, σ=0.74 |

&nbsp;

> **Reproducibility note:** The benchmark uses k=5 retries in `experiment_runner.py`. The default `MAX_RETRIES=3` in `orchestrator.py` must be overridden to reproduce published results.

### By pillar

| Pillar | Cases | Fixed | Rate |
|---|---|---|---|
| Identity | 9 | 9 | 100% |
| Management | 6 | 6 | 100% |
| Database | 17 | 16 | 94.1% |
| Networking | 15 | 14 | 93.3% |
| Security | 12 | 11 | 91.7% |
| Compute | 23 | 17 | 73.9% |
| Analytics | 13 | 9 | 69.2% |
| Storage | 10 | 6 | 60.0% |

&nbsp;

---

## Setup

```bash
git clone https://github.com/hira299/sentinel-mesh
cd sentinel-mesh
make install
```

Copy `.env.example` to `.env` and add your API keys:

```
CEREBRAS_API_KEY=...
GEMINI_API_KEY=...
GROQ_API_KEY=...
```

---

## Usage

```bash
# Run full benchmark
make benchmark

# Generate result figures
make visualize

# Single file run
make run
```

Results are written to `logs/research_data_v100.csv`. Figures are saved to `logs/`.

---

## Project structure

```
sentinel-mesh/
├── benchmark/
│   └── test_cases/          # 105 Terraform misconfiguration test cases
├── core/
│   ├── verifier.py          # Z3 SMT verifier and Cloud Perimeter Model (2,591 lines)
│   ├── orchestrator.py      # closed-loop remediation orchestrator (MAX_RETRIES=3)
│   └── llm_agent.py         # LLM patch generation agent (Cerebras/Gemini/Groq rotation)
├── parsers/
│   └── hcl_to_json.py       # Terraform HCL parser
├── experiment_runner.py     # batch benchmark runner (uses k=5 retries)
├── visualizer.py            # result figure generation
├── logs/                    # generated outputs (gitignored)
├── Makefile
└── requirements.txt
```

---

## Dependencies

- Python 3.10+
- z3-solver
- python-hcl2
- matplotlib
- cerebras-cloud-sdk
- See `requirements.txt` for full list

---

## Citation

If you use this work, please cite:

```bibtex
@misc{sentinelmesh2026,
  title   = {Sentinel-Mesh: Neuro-Symbolic Autonomous Remediation of Cloud Misconfigurations},
  author  = {Hira Ahmed},
  year    = {2026},
  url     = {https://github.com/hira299/sentinel-mesh}
}
```

---

## License

MIT
