# Sentinel-Mesh: A Neuro-Symbolic Framework for Formally Verified Remediation of Cloud Misconfigurations

### 📊 Includes CloudFix-Bench: A Formally Verifiable Benchmark for Autonomous Cloud Infrastructure Repair ($N=105$)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21492985.svg)](https://doi.org/10.5281/zenodo.21492985)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

Sentinel-Mesh is a formal-methods-guided framework for the autonomous remediation of cloud infrastructure misconfigurations defined in Terraform Infrastructure-as-Code (IaC). By combining multi-provider Large Language Models (LLMs) with Z3 SMT formal verification in a closed feedback loop, Sentinel-Mesh guarantees that generated security patches conform to formal cloud perimeter invariants prior to deployment.

---

## Technical Resources

- **Zenodo Archived Dataset & DOI:** [10.5281/zenodo.21492985](https://doi.org/10.5281/zenodo.21492985)
- **Medium Technical Deep-Dive:** [Beyond Heuristics: Formally Verifying AI-Generated Infrastructure with Z3 SMT Solvers](https://medium.com/@hira229922/beyond-heuristics-formally-verifying-ai-generated-infrastructure-with-z3-smt-solvers-e95fd3a7bf95)

---

## Architecture & How It Works

Sentinel-Mesh operates through a 5-step closed-loop neuro-symbolic feedback cycle:

1. **Misconfiguration Ingestion & Parsing:** Terraform HCL configurations are ingested and transformed into JSON Abstract Syntax Trees (AST) via `parsers/hcl_to_json.py`, which are then mapped to Z3 SMT logical formulas representing resource configurations and environment parameters.
2. **Candidate Patch Generation:** A zero-shot LLM agent (supporting Cerebras, Gemini, and Groq backends with multi-provider rotation) receives the AST representation alongside detected vulnerability contexts to synthesize targeted HCL remediation patches.
3. **SMT Gatekeeper Verification:** The candidate patch is passed to the Z3 SMT formal verifier (`core/verifier.py`), which evaluates the patch against strict Cloud Perimeter Model (CPM) security invariants (network isolation, enforced encryption at rest/transit, and defense-in-depth).
4. **Closed-Loop Feedback & Refinement:** If verification fails, Z3 produces a concrete counterexample witness ($SAT$ model). This formal error trace is reinjected verbatim into the LLM prompt context, enabling targeted patch refinement across up to $k=5$ iterations.
5. **Pattern 3 Dual-Solver Proof Certification:** For high-risk security policies, Sentinel-Mesh executes Pattern 3 dual-solver Z3 refinement (Solver A for completeness, Solver B for non-regression) to generate an independently checkable Formal Proof Certificate verifying zero remaining invariant violations.

---

## Empirical Benchmark Results (CloudFix-Bench)

Sentinel-Mesh was evaluated on **CloudFix-Bench**, a comprehensive benchmark dataset consisting of $N=105$ hand-crafted Terraform misconfigurations spanning 8 core cloud infrastructure pillars and 60+ AWS service types.

### Overall Performance Indicators

| Metric | Value | 95% Wilson Confidence Interval |
|---|---|---|
| **Full Sentinel-Mesh Remediation Rate (RR)** | **88/105 (83.81%)** | **[75.59%, 89.64%]** |
| **One-Shot Resolution Rate ($k=1$)** | 85.23% (75/88) | [62.15%, 79.19%] |
| **Controlled No-Witness Ablation Rate** | 68/105 (64.76%) | [55.25%, 73.23%] |
| **Checkov Static Linter Baseline Rate** | 37/105 (35.24%) | [26.77%, 44.75%] |
| **External Wild IaC Generalisability Rate** | 6/12 (50.00%) | [25.38%, 74.62%] |
| **Formal Proof Certificates Issued** | 29 / 105 (27.62%) | N/A |
| **Security Regression Rate** | **0.0%** | **[0.00%, 3.45%]** |

### Per-Pillar Remediation Breakdown

| Infrastructure Pillar | Total Cases ($N$) | Fixed Cases | Remediation Rate (%) | Formal Certs Issued |
|---|---|---|---|---|
| Management | 7 | 7 | 100.0% | 1 |
| Identity | 9 | 9 | 100.0% | 0 |
| Database | 17 | 16 | 94.1% | 13 |
| Networking | 15 | 14 | 93.3% | 2 |
| Security | 11 | 9 | 81.8% | 4 |
| Compute | 22 | 16 | 72.7% | 4 |
| Analytics | 14 | 10 | 71.4% | 4 |
| Storage | 10 | 7 | 70.0% | 1 |
| **Total / Overall** | **105** | **88** | **83.81%** | **29** |

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

Sentinel-Mesh includes a complete command-line suite for benchmark execution, baseline comparisons, ablation studies, and dynamic visualization:

1. **Primary Benchmark Evaluation:**
   Run the core neuro-symbolic remediation loop across CloudFix-Bench with your chosen provider:
   ```bash
   python core/experiment_runner.py --provider groq
   ```
   Available providers: `groq`, `gemini`, `cerebras`.

2. **Static Linter Baseline Comparison:**
   Evaluate static analysis baseline performance using Checkov rules:
   ```bash
   python core/checkov_baseline_runner.py --provider groq
   ```

3. **Controlled Ablation Study:**
   Run the ablation benchmark without Z3 counterexample feedback (no-witness mode):
   ```bash
   python core/ablation_no_witness_runner.py --provider groq
   ```

4. **External Wild IaC Evaluation:**
   Evaluate Sentinel-Mesh generalizability against real-world external Terraform configurations:
   ```bash
   python core/external_wild_runner.py --provider groq
   ```

5. **Dynamic Result Visualizer:**
   Generate publication-grade figures and statistical plots dynamically from raw CSV log data:
   ```bash
   python core/visualizer.py
   ```

6. **95% Wilson Confidence Interval Calculator:**
   Compute exact binomial confidence bounds for all experimental conditions:
   ```bash
   python -m core.compute_ci
   ```

---

## Repository Structure

```
sentinel-mesh/
|-- benchmark/
|   |-- external_wild_cases/   # External real-world Terraform misconfigurations (N=12)
|   |-- test_cases/            # CloudFix-Bench suite (N=105 test cases)
|   `-- rules.json             # Formal security rule definitions
|-- core/
|   |-- ablation_no_witness_runner.py  # Controlled ablation runner without witness feedback
|   |-- check_initial_verdicts.py      # Verification validator for ground truth states
|   |-- checkov_baseline_runner.py     # Checkov static linter baseline harness
|   |-- compute_ci.py                 # 95% Wilson score confidence interval calculator
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

If you use **CloudFix-Bench** or the **Sentinel-Mesh** framework in your research or tooling, please cite our work as follows:

```
@article{ahmed2026sentinelmesh,
  author       = {Ahmed, Hira and Saad, Muhammad and Shaikh, Muhammad Kashif and Naseem, Muhammad and Zaki, Hassan and Rasheed, Muhammad Rehan},
  title        = {{Sentinel-Mesh: A Neuro-Symbolic Framework for Formally Verified Remediation of Cloud Misconfigurations}},
  journal      = {arXiv preprint},
  year         = {2026},
  doi          = {10.5281/zenodo.21492985},
  url          = {https://doi.org/10.5281/zenodo.21492985}
}
```

### License

This project is licensed under the terms of the MIT License.
```
---