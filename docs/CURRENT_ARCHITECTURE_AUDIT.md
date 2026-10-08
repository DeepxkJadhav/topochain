# TopoChain — Current Architecture Audit

**Audit Date:** 2026-10-08  
**Scope:** Complete Codebase, Test Suite, Data Structures, and Algorithmic Flow

---

## 1. Executive Summary of Audit

The existing TopoChain repository establishes a functional proof-of-concept pipeline centered on:
$$\text{AST / Dependency Manifests} \longrightarrow \text{Weighted Graph} \longrightarrow \text{Vietoris-Rips Filtration} \longrightarrow \text{Persistent Homology} \longrightarrow \text{TNN Latent Space} \longrightarrow \text{Z-Score Anomaly}$$

All 18 initial tests are passing. However, the system currently operates under the monolithic assumption that **topological drift is the sole primary detector of supply chain compromise**, with basic heuristic checks retrofitted onto diagnosis strings. To become an enterprise-grade multimodal integrity verification platform, the system must treat topology as **one independent signal among five orthogonal channels** (AST/Structure, Dependency Intelligence, Topology, Semantics, Git Evolution, and Optional Sandbox).

---

## 2. Inventory of Implemented Modules

| Module Path | Primary Classes / Functions | Operational Status | Quality & Design Assessment |
|---|---|---|---|
| `topochain/core/extractor/base.py` | `CodeEntity`, `DependencyEntity`, `ExtractionResult`, `EntityType` | **Implemented** | Clean dataclasses; lacks semantic taint markers and fine-grained capability tags. |
| `topochain/core/extractor/python_extractor.py` | `PythonASTExtractor` | **Implemented** | Uses Python's native `ast`; parses functions, classes, calls, cyclomatic complexity, and basic sensitive calls. |
| `topochain/core/extractor/js_extractor.py` | `JavaScriptExtractor` | **Incomplete** | Uses regex heuristics for functions and imports; fragile on modern TypeScript/ESM syntax and nested blocks. |
| `topochain/core/extractor/dependency_extractor.py` | `DependencyExtractor` | **Incomplete** | Supports `requirements.txt`, basic `package.json`, `pyproject.toml`, `go.mod`. Implements Damerau-Levenshtein distance. Missing `Cargo.toml`, `Cargo.lock`, `poetry.lock`, lifecycle script extraction, and dependency confusion analysis. |
| `topochain/core/extractor/codebase_extractor.py` | `CodebaseExtractor` | **Implemented** | Recursively traverses repositories; lacks path traversal sanitization and symlink recursion bounds. |
| `topochain/core/graph/weighting.py` | `TopologicalMetricWeighting` | **Implemented** | Computes edge weights ($0.15$ to $0.75$) modulated by complexity and sensitivity. Metric properties require strict formal bounds. |
| `topochain/core/graph/builder.py` | `GraphBuilder`, `CodeGraphResult` | **Implemented** | Builds `networkx.DiGraph` and computes Dijkstra shortest-path distance matrix bounded at $D_{\max}=1.0$. Missing sparse/reduction handling for large repos. |
| `topochain/core/topology/homology.py` | `PersistentHomologyEngine`, `PersistenceDiagramSet` | **Implemented** | Wraps `ripser.ripser` for $H_0, H_1, H_2$ persistent homology, Betti numbers, and persistence entropy. |
| `topochain/core/topology/pers_image.py` | `PersistenceImageConverter` | **Implemented** | Converts birth-persistence diagrams into $(3, 32, 32)$ Gaussian-smoothed image tensors. |
| `topochain/core/topology/visualizer.py` | `TopologicalVisualizer` | **Implemented** | ASCII barcodes in terminal and matplotlib PNG plot generation. |
| `topochain/core/drift/detector.py` | `TopologicalDriftDetector`, `DriftResult` | **Mathematically Inconsistent** | Tracks scalar step drift, but baseline stats and centroid logic conflate scalar drift distribution with vector space centroid. |
| `topochain/core/drift/diagnostics.py` | `TopologicalDiagnosticsEngine` | **Partially Implemented** | Detects `LOOP_BIRTH_ANOMALY` and `UNCONNECTED_ISLAND_INJECTION`; lacks multimodal semantic and git correlation. |
| `topochain/core/db/storage.py` | `StorageEngine` | **Incomplete / Vulnerable** | SQLite database with safe context manager; automatically updates baseline on non-anomalous commits (vulnerable to slow-drift baseline poisoning). |
| `topochain/ai/models/tnn.py` | `TopologicalNeuralNetwork`, `ResidualBlock` | **Implemented (Premature)** | 2D CNN mapping persistence images to $\mathbb{S}^{63}$; built before scientific ablation proved its necessity over simpler TDA baselines. |
| `topochain/ai/training/trainer.py` | `TopologicalTrainer`, `ContrastiveHomologyLoss` | **Implemented** | Triplet margin training pipeline. |
| `topochain/ai/inference/engine.py` | `TNNInferenceEngine` | **Implemented** | Deterministic CPU evaluation runner. |
| `topochain/data/synthetic/attack_generator.py` | `SyntheticAttackGenerator` | **Incomplete** | Contains 4 hardcoded synthetic injectors; lacks structured metadata (`attack_id`, `ground_truth`) and has no **topology-preserving** attacks. |
| `topochain/data/datasets/loader.py` | `BenchmarkRepoGenerator` | **Implemented** | Generates a 3-file Python mock microservice for testing. |
| `topochain/core/orchestrator.py` | `TopoChainOrchestrator` | **Incomplete** | Orchestrates single-pipeline scan; missing independent multimodal signals, baseline governance, and 3-state decisions (`SAFE`, `REVIEW`, `BLOCK`). |
| `topochain/cli/main.py` | Click CLI | **Incomplete** | Has `init`, `scan`, `demo`, `serve`. Missing `history`, `explain`, `baseline status/approve`, `attack-test`, `benchmark`, `report`. |
| `topochain/api/server.py` | FastAPI Server | **Implemented** | Endpoints for `/health`, `/api/v1/scan`, `/api/v1/projects/{id}/history`. |

---

## 3. Identification of Broken Code & Mathematical Inconsistencies

1. **Drift Mathematics Flaw (Section 16 / Section 18 of Master Spec):**
   - In `topochain/core/drift/detector.py`:
     ```python
     step_drift = float(np.linalg.norm(current_emb - prev_emb))
     z_score = float((step_drift - baseline_mean) / baseline_std)
     ```
     While `step_drift` is scalar, the original concept attempted to mix embedding centroids with scalar baseline statistics. Scalar drift distribution statistics ($\mu_\Delta, \sigma_\Delta^2, \text{quantiles}(\Delta)$) must be formally isolated from latent vector centroid and dispersion statistics.
   - Zero-variance protection: `baseline_std = np.sqrt(max(0.0, baseline_variance) + self.epsilon)` needs explicit epsilon guard ($10^{-8}$) and fallback when sample count $N < 3$.
   - Quantile tracking ($p_{50}, p_{90}, p_{99}$) is completely absent.

2. **Binary Decision Flaw:**
   - The decision engine evaluates `is_anomaly = bool(z_score > threshold or len(defects) > 0)`.
   - This creates a strict binary outcome (`PASSED` vs `ANOMALY_DETECTED`).
   - A legitimate large refactor (e.g. migrating 10 modules) causes high topological change and is incorrectly flagged as a malicious attack instead of triaged as `REVIEW`.

---

## 4. Identification of Incorrect Assumptions

1. **"Malicious code always produces a topological defect":**
   - **False.** In-place modification of existing functions (e.g., swapping `if role == 'admin':` to `if True:`, or altering an existing SQL query) preserves the exact graph topology while altering semantic behavior.
2. **"TNN is required for topological drift":**
   - **Unproven.** The TNN was built prior to evaluating classical, mathematically rigorous, parameter-free TDA baselines (e.g., Wasserstein distance $W_1$, Bottleneck distance $d_B$, or direct persistence image Frobenius distance).
3. **"Automatic baseline updating is safe":**
   - **False.** In `orchestrator.py`, any commit with $Z \le 3.0$ automatically updates running mean and variance. An attacker executing a slow-drift boiling-frog attack can shift the baseline over 30 commits without triggering an alert.

---

## 5. Security & Safety Problems in TopoChain Itself

1. **Unbounded Path Traversal:**
   `CodebaseExtractor` and `DependencyExtractor` accept arbitrary directory paths without asserting canonical resolution inside target boundaries.
2. **Untrusted Subprocess / Host Execution:**
   No safe sandbox exists. If test scripts execute repository code directly on the developer host, untrusted code could compromise the host environment.
3. **Resource Exhaustion on Large Graphs:**
   Ripser persistent homology has worst-case $O(N^3)$ computational complexity. A repository with 10,000 nodes could lock the CPU or cause out-of-memory crashes without tiered graph reduction.

---

## 6. Audit of Existing Test Suite

- **Tests Passing:** 18 out of 18 tests passing.
- **Coverage Summary:**
  - Unit tests for AST parser, JS regex extractor, dependency typosquatting, Dijkstra metric matrix, Ripser persistent homology, persistence image generator, TNN architecture, contrastive loss, drift calculation, SQLite storage, CLI invocation, and FastAPI endpoints.
- **Critical Test Gaps:**
  - Zero tests for topology-preserving attacks.
  - Zero tests for Cargo (`Cargo.toml`, `Cargo.lock`) or Poetry (`poetry.lock`).
  - Zero tests for npm lifecycle scripts (`postinstall`, `preinstall`).
  - Zero tests for baseline poisoning / gradual drift evasion.
  - Zero ablation study tests measuring Precision/Recall/ROC-AUC of topology vs. simpler baselines.
  - Zero tests for 3-state decisions (`SAFE`, `REVIEW`, `BLOCK`).
  - Zero tests for path traversal or resource exhaustion.
