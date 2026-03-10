# Sentinel-Mesh

Neuro-symbolic framework for autonomous remediation of cloud infrastructure misconfigurations. Combines LLM-driven patch generation with Z3 SMT formal verification in a closed feedback loop.

## How it works

1. A Terraform misconfiguration is detected and passed to the LLM agent
2. The agent generates a remediation patch
3. The Z3 verifier checks the patch against formal security invariants (Cloud Perimeter Model)
4. If the patch fails verification, it is rejected and the loop retries
5. Once the patch satisfies all invariants, a formal proof certificate is issued

The verifier acts as a closed-loop acceptance oracle — the LLM cannot produce a patch that passes without satisfying the formal constraints.

## Benchmark results

Evaluated on 105 real-world Terraform misconfiguration patterns across 8 cloud infrastructure pillars.

| Metric | Result |
|---|---|
| Overall remediation rate | 88/105 (83.8%) |
| One-shot resolution rate | 85.2% |
| Formal proof certificates issued | 37 |
| LLM hallucination rate | 16.2% |

### By pillar

| Pillar | Cases | Fixed | Rate |
|---|---|---|---|
| Identity | 9 | 9 | 100% |
| Management | 6 | 6 | 100% |
| Database | 17 | 16 | 94.1% |
| Security | 12 | 11 | 91.7% |
| Networking | 15 | 14 | 93.3% |
| Compute | 23 | 17 | 73.9% |
| Analytics | 13 | 9 | 69.2% |
| Storage | 10 | 6 | 60.0% |

## Setup

```bash
git clone https://github.com/your-username/sentinel-mesh
cd sentinel-mesh
make install
```

Copy `.env.example` to `.env` and add your API keys:

```
LLM_API_KEY=...
LLM_PROVIDER=...       # cerebras / gemini / groq
```

## Usage

```bash
# Run full benchmark
make benchmark

# Generate result figures
make visualize

# Single run
make run
```

Results are written to `logs/research_data_v100.csv`. Figures are saved to `logs/`.

## Project structure

```
sentinel-mesh/
├── benchmark/
│   ├── test_cases/        # 105 Terraform misconfiguration test cases
│   └── rules.json         # verification rule definitions
├── core/
│   ├── verifier.py        # Z3 SMT verifier and Cloud Perimeter Model
│   ├── orchestrator.py    # closed-loop remediation orchestrator
│   ├── llm_agent.py       # LLM patch generation agent
│   ├── experiment_runner.py
│   └── visualizer.py      # result figure generation
├── parsers/
│   └── hcl_to_json.py     # Terraform HCL parser
├── tests/
├── logs/                  # generated outputs (gitignored)
├── Makefile
└── requirements.txt
```

## Dependencies

- Python 3.10+
- z3-solver
- python-hcl2
- matplotlib / seaborn
- See `requirements.txt` for full list

## Citation

If you use this work, please cite:

```bibtex
@misc{sentinelmesh2025,
  title   = {Sentinel-Mesh: Neuro-Symbolic Autonomous Remediation of Cloud Misconfigurations},
  author  = {Your Name},
  year    = {2025},
  url     = {https://github.com/your-username/sentinel-mesh}
}
```

## License

MIT