# TopoChain Empirical Ablation Experiment Protocol

## 1. Experimental Objective
The primary goal of this empirical experiment is to validate the central research hypothesis of TopoChain:

> **Hypothesis**: Algebraic topology (persistent homology drift) provides a valuable structural security signal, but **cannot reliably detect supply chain attacks in isolation**. A calibrated multimodal fusion combining Topology, Dependency Intelligence, Semantic Capability Analysis, and AST dynamics significantly outperforms any single-signal detector in both recall and false positive suppression.

---

## 2. Benchmark Corpus Design

To ensure an unbiased, scientifically reproducible assessment, the benchmark dataset contains 4 distinct classes of codebase evolutions:

| Category | Count | Ground Truth | Topology Changing? | Description |
|---|---|---|---|---|
| **Benign Normal** | 2 | Benign (`0`) | Minimal | Documentation edits, simple utility additions. |
| **Benign Refactor** | 2 | Benign (`0`) | High (`Yes`) | Modularization, class wrapping, method extraction. |
| **Topology-Changing Attacks** | 5 | Malicious (`1`) | High (`Yes`) | Typosquatting, dependency confusion, postinstall hooks, call graph hijacking, obfuscated payloads. |
| **Topology-Preserving Attacks** | 2 | Malicious (`1`) | None (`No`) | In-place conditional auth bypass, in-place credential theft. |

---

## 3. Evaluated System Configurations (Ablation Matrix)

| Config ID | Architecture | Channel Weights | Rationale |
|---|---|---|---|
| **A** | AST-Only | AST: 1.0, others: 0.0 | Pure syntactic/graph node delta baseline |
| **B** | Dependency-Only | Dep: 1.0, others: 0.0 | Traditional SCA manifest checking baseline |
| **C** | Semantic-Only | Semantic: 1.0, others: 0.0 | Static AST pattern & capability matching |
| **D** | Topology-Only | Topology: 1.0, others: 0.0 | Monolithic Persistent Homology drift (Legacy TopoChain) |
| **E** | AST + Dependency | AST: 0.5, Dep: 0.5 | Combined syntax + package inspection |
| **F** | Dependency + Semantic | Dep: 0.5, Semantic: 0.5 | Industry SAST + SCA baseline |
| **G** | Multimodal (No Topology) | Dep: 0.40, Sem: 0.35, AST: 0.15, Git: 0.10 | Complete system excluding Persistent Homology |
| **H** | Full Multimodal (With Topology) | Dep: 0.30, Sem: 0.30, Topo: 0.20, AST: 0.10, Git: 0.10 | Complete TopoChain Multimodal Fusion Platform |

---

## 4. Evaluation Metrics & Statistical Formulas

All metrics are computed using `scikit-learn (v1.9.1)`:

1. **Precision**:
   $$\text{Precision} = \frac{TP}{TP + FP}$$
2. **Recall**:
   $$\text{Recall} = \frac{TP}{TP + FN}$$
3. **F1-Score**:
   $$F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$
4. **ROC-AUC**: Area under Receiver Operating Characteristic curve computed over continuous risk scores $y_{\text{score}} \in [0, 1]$.
5. **PR-AUC**: Precision-Recall Area Under Curve (Average Precision) for imbalanced security event distributions.
6. **Refactor False Positive Rate ($\text{FPR}_{\text{refactor}}$)**:
   $$\text{FPR}_{\text{refactor}} = \frac{\text{False Positives on Benign Refactors}}{\text{Total Benign Refactors}}$$
7. **Topology-Preserving False Negative Rate ($\text{FNR}_{\text{in-place}}$)**:
   $$\text{FNR}_{\text{in-place}} = \frac{\text{Missed In-Place Backdoors}}{\text{Total Topology-Preserving Attacks}}$$
8. **Inference Latency**: Mean wall-clock processing time per commit (in milliseconds).

---

## 5. Execution Command
To reproduce the experiment and re-run all 8 configurations end-to-end:
```bash
topochain benchmark --output-json docs/ABLATION_RESULTS.json
```
