# TopoChain — Gap Analysis

This document details the functional, architectural, scientific, and security gaps between the initial proof-of-concept and the target multimodal supply chain verification platform.

---

## 1. Subsystem-by-Subsystem Gap Matrix

| Subsystem | Master Specification Requirement | Current Implementation State | Gap Level | Technical Deficit Description |
|---|---|---|---|---|
| **AST / Structural Analysis** | JS, TS, Python; AST, functions, classes, calls, control flow, exception paths, data flows, dynamic execution. | Native Python AST parser; regex-based JS parser. | **High** | JS/TS lacks robust AST extraction; data flow relationships and control-flow changes are not tracked as independent metrics. |
| **Dependency Intelligence** | npm, Python, Go, Rust. Package changes, lockfiles, lifecycle scripts (`postinstall`), name similarity, dependency confusion, capabilities. | Parses `requirements.txt`, basic `package.json`, `pyproject.toml`, `go.mod`. Levenshtein typosquatting. | **Critical** | Missing Rust (`Cargo.toml`, `Cargo.lock`), Poetry (`poetry.lock`), npm lockfiles (`package-lock.json`), npm lifecycle scripts, and dependency confusion detection. |
| **Topological Analysis** | Separable topologies (AST, CFG, Call graph, Dependency graph); inconclusive state reporting; multiple persistence representations. | Single combined graph; single metric distance matrix; single persistence image. | **High** | Cannot isolate *which* topology drifted (e.g. dependency drift vs. call graph drift). Cannot report when topology is inconclusive. |
| **Drift Mathematics** | $\Delta = \|\mathbf{z}_t - \mathbf{z}_{t-1}\|_2$; $Z = \frac{\Delta - \mu_\Delta}{\sqrt{\sigma_\Delta^2 + 10^{-8}}}$; quantile tracking ($p_{50}, p_{90}, p_{99}$); isolation of scalar and vector stats. | Single step-drift calculation; no quantile tracking; potential confusion between vector centroid and scalar drift stats. | **High** | Lacks formal scalar drift distribution tracking, quantile calculation, and explicit numerical guardrails against zero variance or small sample sizes. |
| **Attack Simulation** | Structured synthetic attacks with metadata (`attack_id`, `ground_truth`, `is_topology_changing`); topology-preserving and topology-changing attacks. | 4 unstructured mutating helper functions; all synthetic attacks assume topological changes. | **Critical** | Missing topology-preserving attacks (in-place logic tampering), credential theft, data exfiltration, postinstall execution, and structured benchmark schema. |
| **Semantic Analysis** | Sensitive APIs, credential access, auth/authz logic, dynamic execution, environment access, serialization, exfiltration indicators. | Basic list of 25 sensitive pattern strings checked during AST extraction. | **High** | No dedicated semantic engine; no detection of semantic intent divergence when code topology remains static. |
| **Git Evolution Analysis** | Commit velocity, author entropy, lines churned, unusual commit timing, out-of-band authors, deviation from historical evolution. | None. Single snapshot directory analysis. | **High** | Complete absence of commit history and developer behavior signals. |
| **Baseline Protection** | Known-good anchor, manual approval workflow (`baseline approve`), immutable reference, gradual drift tracking, baseline audit log. | Automatic baseline update whenever commit is not flagged anomalous. | **Critical** | Highly vulnerable to boiling-frog baseline poisoning attacks. Lacks anchor immutability and approval governance. |
| **Multimodal Risk Fusion** | Central fusion engine combining Topology, AST, Dependency, Semantic, Git, and Runtime scores into unified risk score and confidence. | Rudimentary anomaly escalation based on topological drift and diagnostic string matches. | **Critical** | No calibrated risk fusion; no independent confidence scoring; decisions are hard-coupled to topology. |
| **Decision Engine** | Three explicit states: `SAFE`, `REVIEW`, `BLOCK`. Major refactors must trigger `REVIEW`, not `BLOCK`. | Binary states: `PASSED` vs `ANOMALY_DETECTED`. | **High** | Large legitimate refactors with high topological drift are misclassified as attacks rather than routed for human review. |
| **Explainability** | Full evidence card detailing signal scores, changed files, primary findings, and actionable recommendations. | Terminal summary table and diagnostic text list. | **Medium** | Missing drill-down explainability linking composite risk back to exact files, lines, and AST entities. |
| **Scientific Validation & Ablation** | Baseline comparison ($A$ through $H$): AST-only, Dep-only, Semantic-only, Topology-only, Combinations, and Full $\pm$ Topology. Metrics: Precision, Recall, F1, ROC-AUC. | Direct jump to TNN model without experimental justification. | **Critical** | Lacks experimental proof demonstrating whether persistent homology outperforms simpler structural/dependency baselines. |
| **Behavioral Sandbox** | Optional isolated runtime observation (processes, filesystem, network, DNS) without executing untrusted code on host. | None. | **Medium** | No runtime observation capability for suspicious dependencies or postinstall scripts. |
| **CLI & CI/CD** | `init`, `scan`, `history`, `explain`, `baseline status`, `baseline approve`, `attack-test`, `benchmark`, `report`. | `init`, `scan`, `demo`, `serve`. | **Medium** | Missing administrative baseline management, explainability CLI, and benchmark execution commands. |
| **Self-Security & Hardening** | Path traversal protection, parser timeout guards, graph size caps, safe parsing limits. | Basic file opening without canonical path sandboxing or graph size fencing. | **High** | Vulnerable to crafted malicious repositories causing denial-of-service or path escape. |
| **Performance Architecture** | Tiered strategy: small (exact), medium (optimized), large (graph reduction), monorepo (hierarchical). | Exact Dijkstra and full Ripser on all graphs up to 400 nodes. | **Medium** | Will encounter exponential memory and runtime scaling on larger codebases. |

---

## 2. Priority Risk Summary

1. **False Sense of Security from Topology Alone**: An attacker modifying logic inside existing functions evades current TopoChain entirely because no topological defect is created.
2. **False Positives on Legitimate Architectural Evolution**: A clean refactor that splits a module into two creates high topological drift and is blocked by the binary decision engine.
3. **Model Poisoning**: An attacker committing small, subtle changes sequentially shifts the baseline unnoticed because the current system automatically updates baseline statistics without a trust gate.
4. **Unvalidated Research Claim**: The current documentation describes the TNN as essential without having performed an ablation study against simple structural diffing or unlearned persistence diagrams.
