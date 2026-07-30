# CloudFix-Bench Dataset Guide ($N=105$)

**CloudFix-Bench** is a formally verifiable benchmark consisting of $N=105$ hand-crafted AWS Terraform (HCL2) misconfigurations across 8 cloud security pillars and 60+ AWS service types.

---

## Terms of Use & Mandatory Citation Notice

1. **Academic & Commercial Integrity:** CloudFix-Bench is archived on **Zenodo (DOI: [10.5281/zenodo.20975067](https://doi.org/10.5281/zenodo.20975067))** with a permanent, immutable timestamp credited to **Hira Ahmed et al.**
2. **Attribution Requirement:** Any research paper, tool, or derivative dataset that uses, forks, or adapts these 105 test cases **MUST explicitly cite** the original author (Hira Ahmed) and link to this repository and Zenodo DOI.
3. **Plagiarism Warning:** Re-hosting or publishing these test cases without original author attribution constitutes academic misconduct and copyright infringement under the MIT/Apache license.

---

## Dataset Directory Structure

- `test_cases/`: 105 test folders (`AB_01_...`, `S3_01_...`, etc.), each containing a vulnerable `main.tf` configuration.
- `external_wild_cases/`: 12 uncurated real-world Terraform files drawn from open-source GitHub repositories for generalisability evaluation.
- `rules.json`: Formal specification rules for ground-truth verification.

---

## How to Benchmark Your Own Model / Tool

If you are evaluating your own LLM or verification framework against CloudFix-Bench:

1. Each test case in `benchmark/test_cases/` is engineered to fail an initial Z3 CPM safety check.
2. Supply your candidate remediation model with the `main.tf` source code.
3. Compare your model's generated fix against our Z3 SMT oracle using `python core/experiment_runner.py`.

### Citation Block

```bibtex
@misc{ahmed2026cloudfixbench,
  author       = {Hira Ahmed},
  title        = {{CloudFix-Bench: A Formally Verifiable Benchmark for Autonomous Cloud Infrastructure Repair}},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.20975067},
  url          = {https://doi.org/10.5281/zenodo.20975067}
}