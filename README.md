# Sentinel-Mesh: Neuro-Symbolic Autonomous Remediation of Cloud Infrastructure Misconfigurations

Sentinel-Mesh is a formal-methods-guided framework for the autonomous remediation of cloud infrastructure misconfigurations defined in Terraform Infrastructure-as-Code (IaC). By combining multi-provider Large Language Models (LLMs) with Z3 SMT formal verification in a closed feedback loop, Sentinel-Mesh guarantees that generated security patches conform to formal cloud perimeter invariants prior to deployment.

---

## Technical Resources

- Zenodo Concept DOI: [https://doi.org/10.5281/zenodo.20975067](https://doi.org/10.5281/zenodo.20975067)
- Medium Technical Deep-Dive: [Autonomous Cloud Security with Sentinel-Mesh](https://medium.com/@hira-ahmed/sentinel-mesh-neuro-symbolic-remediation)

---

## Architecture & How It Works

Sentinel-Mesh operates through a 5-step closed-loop neuro-symbolic feedback cycle:

1. Misconfiguration Ingestion & Parsing: Terraform HCL configurations are ingested and transformed into JSON Abstract Syntax Trees (AST) via `parsers/hcl_to_json.py`, which are then mapped to Z3 SMT logical formulas representing resource configurations and environment parameters.
2. Candidate Patch Generation: A fine-tuned LLM agent (supporting Cerebras, Gemini, and Groq backends) receives the AST representation alongside detected vulnerability contexts to synthesize targeted HCL remediation patches.
3. SMT Gatekeeper Verification: The candidate patch is passed to the Z3 SMT formal verifier (`core/verifier.py`), which evaluates the patch against strict Cloud Perimeter Model security invariants (such as non-public access policies, enforced encryption at rest/transit, and isolated network perimeters).
4. Closed-Loop Feedback & Refinement: If verification fails, Z3 produces unsat core counterexample feedback. This formal error trace is reinjected into the LLM prompt context, enabling targeted patch refinement across up to k=5 iterations.
5. Pattern 3 Dual-Solver Proof Certification: For high-risk security policies (including network perimeter boundaries and cryptographic key configurations), Sentinel-Mesh executes Pattern 3 dual-solver Z3 refinement to generate a mathematically binding Formal Proof Certificate verifying zero remaining invariant violations.

---

## Empirical Benchmark Results (CloudFix-Bench)

Sentinel-Mesh was evaluated on CloudFix-Bench, a comprehensive benchmark dataset consisting of N=105 hand-crafted Terraform misconfigurations spanning 8 core cloud infrastructure pillars.

### Overall Performance Indicators

| Metric | Value |
|---|---|
| Remediation Rate (RR) | 88/105 (83.81%) |
| One-Shot Resolution Rate (k=1) | 85.23% (75/88) |
| Formal Proof Certificates Issued | 29 |
| Hallucinated / Blocked Cases | 17/105 (16.19%) |
| Security Regression Rate | 0.0% |

### Per-Pillar Remediation Breakdown

| Infrastructure Pillar | Total Cases (N) | Fixed Cases | Remediation Rate (%) |
|---|---|---|---|
| Management | 7 | 7 | 100.0% |
| Identity | 9 | 9 | 100.0% |
| Database | 17 | 16 | 94.1% |
| Networking | 15 | 14 | 93.3% |
| Security | 11 | 9 | 81.8% |
| Compute | 22 | 16 | 72.7% |
| Analytics | 14 | 10 | 71.4% |
| Storage | 10 | 7 | 70.0% |
| **Total / Overall** | **105** | **88** | **83.81%** |

---

## Installation & Environment Setup

### Prerequisites

- Python 3.10 or higher
- Git

### Step-by-Step Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/hira299/sentinel-mesh.git
   cd sentinel-mesh
   ```

2. Create and activate a Python virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables:

   Copy `.env.example` to `.env` and set your API keys for the LLM providers:

   ```bash
   cp .env.example .env
   ```

   Edit `.env` to supply valid credentials:

   ```env
   CEREBRAS_API_KEY=your_cerebras_api_key
   GEMINI_API_KEY=your_gemini_api_key
   GROQ_API_KEY=your_groq_api_key
   ```

---

## Execution CLI Suite

Sentinel-Mesh includes a complete command-line suite for benchmark execution, baseline comparisons, ablation studies, and visualization:

1. Primary Benchmark Evaluation:

   Run the core neuro-symbolic remediation loop across CloudFix-Bench with your chosen provider:

   ```bash
   python core/experiment_runner.py --provider groq
   ```

   Available providers: `groq`, `gemini`, `cerebras`.

2. Static Linter Baseline Comparison:

   Evaluate static analysis baseline performance using Checkov rules:

   ```bash
   python core/checkov_baseline_runner.py --provider groq
   ```

3. Controlled Ablation Study:

   Run the ablation benchmark without Z3 counterexample feedback (no-witness mode):

   ```bash
   python core/ablation_no_witness_runner.py --provider groq
   ```

4. External Wild IaC Evaluation:

   Evaluate Sentinel-Mesh generalizability against real-world external Terraform configurations:

   ```bash
   python core/external_wild_runner.py --provider groq
   ```

5. Dynamic Result Visualizer:

   Generate publication-grade figures and statistical plots from log data:

   ```bash
   python core/visualizer.py
   ```

---

## Repository Structure

```
sentinel-mesh/
|-- benchmark/
|   |-- external_wild_cases/   # External real-world Terraform misconfigurations
|   |-- test_cases/            # CloudFix-Bench suite (N=105 test cases)
|   `-- rules.json             # Formal security rule definitions
|-- core/
|   |-- ablation_no_witness_runner.py  # Ablation study runner without witness feedback
|   |-- check_initial_verdicts.py      # Verification validator for ground truth states
|   |-- checkov_baseline_runner.py     # Checkov static linter baseline harness
|   |-- experiment_runner.py          # Primary CloudFix-Bench experiment runner
|   |-- external_wild_runner.py        # External wild IaC evaluation harness
|   |-- llm_agent.py                  # Multi-provider LLM interface module
|   |-- orchestrator.py               # Closed-loop remediation orchestrator engine
|   |-- verifier.py                   # Z3 SMT verifier and Cloud Perimeter Model
|   `-- visualizer.py                 # Dynamic visualizer and figure generator
|-- infrastructure/
|   `-- docker-compose.yml            # Docker composition for sandbox environment
|-- logs/                             # Benchmark CSV output logs and generated figures
|-- parsers/
|   `-- hcl_to_json.py                # Terraform HCL AST parser script
|-- DEV_WORKFLOW.md                   # Developer guidelines and workflow procedures
|-- Makefile                          # Command execution shortcut targets
|-- requirements.txt                  # Python dependency specifications
`-- README.md                         # Framework documentation
```

---

## Citation & License

### Citation

If you use Sentinel-Mesh in your research or project, please cite:

```bibtex
@article{ahmed2026sentinelmesh,
  title   = {Sentinel-Mesh: Neuro-Symbolic Autonomous Remediation of Cloud Infrastructure Misconfigurations},
  author  = {Hira Ahmed et al.},
  year    = {2026},
  url     = {https://github.com/hira299/sentinel-mesh}
  url     = {https://github.com/hira299/sentinel-mesh}
}
```

### License

This project is licensed under the terms of the MIT License.
