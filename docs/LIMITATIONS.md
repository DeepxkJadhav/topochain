# TopoChain System Limitations & Known Constraints

## 1. Mathematical Boundaries of Persistent Homology

### 1.1. Invariance to In-Place Logic Tampering
Algebraic topology on simplicial complexes operates on the relational connectivity (metric space $(V, d_G)$) of code entities. It is mathematically invariant to transformations that preserve graph isomorphism:
- **Condition Inversions**: Changing `if authenticated:` to `if not authenticated:` does not alter nodes or edges.
- **Literal Modification**: Changing an API URL string, cryptographic key constant, or timeout threshold inside an existing function leaves Betti numbers ($H_0, H_1, H_2$) unchanged.
- **Topological Drift**: $\Delta = \|\mathbf{z}_t - \mathbf{z}_{t-1}\|_2 = 0.0$.

*Remediation in TopoChain*: In-place changes are delegated to the **Semantic Analysis Engine** and **Dependency Intelligence Subsystem**, rather than relying on topological invariants.

---

## 2. Computational Complexity & Scalability

### 2.1. Combinatorial Growth of Simplicial Complexes
The Vietoris-Rips complex $\text{VR}(G, \epsilon)$ has theoretical worst-case complexity of $\mathcal{O}(2^N)$ simplices for an $N$-node graph. Although modern matrix reduction algorithms (Ripser) run efficiently on sparse complexes:
- Exact all-pairs shortest paths via Dijkstra requires $\mathcal{O}(|V| \cdot |E| + |V|^2 \log |V|)$.
- Computing $H_k$ for $k \ge 3$ becomes computationally prohibitive for real-time CI/CD blocking gates.

*Mitigation in TopoChain*:
- Dimension truncation: Persistent homology is bounded to $k \le 2$ ($H_0, H_1, H_2$).
- Node capping: `GraphBuilder` prunes graphs to $N \le 400$ using degree and centrality metrics before metric distance calculation, ensuring commit scans finish in under 20 milliseconds.
- Repository decomposition: Monolithic codebases exceeding 5,000 functions should be partitioned into package/service boundaries.

---

## 3. Dynamic Language Introspection & Reflection

### 3.1. Dynamic Dispatch and Runtime Code Generation
In interpreted languages (Python, JavaScript):
- Code can dynamically construct imports via `importlib.import_module("ev" + "il")`.
- Code can execute strings at runtime via `eval(b64decode(...))`.
- Monkey-patching can dynamically swap method pointers at runtime without modifying AST call nodes.

*Mitigation in TopoChain*:
- The Semantic Analyzer flags the invocation of dangerous dynamic sinks (`eval`, `exec`, `__import__`).
- The optional Behavioral Sandbox observes runtime process and network invocations. However, full static recovery of dynamically generated execution graphs remains undecidable (Rice's Theorem).

---

## 4. Sensitivity to Major Architectural Refactorings

### 4.1. Legitimate Homological Disruption
When a project undergoes a major architectural overhaul:
- Migrating from synchronous function calls to asynchronous event-driven queues.
- Splitting monolithic controllers into domain-driven repositories.
- Extracting inline database queries into an ORM abstraction.

The topological invariants naturally undergo significant drift ($\Delta > 0.40$). While TopoChain's `DecisionEngine` uses cross-channel corroboration to route clean refactors to `REVIEW` instead of `BLOCK`, such transitions require human security leads to manually anchor the new baseline:
```bash
topochain baseline approve <refactor_commit> --approver "lead_architect" --reason "V2 modularization"
```

---

## 5. Model Governance & Operational Discipline

### 5.1. The Need for Human-in-the-Loop Signoff
Automated security systems that update their internal baseline models automatically on every green commit are vulnerable to **slow-drift model poisoning**. TopoChain addresses this by enforcing:
1. Immutable trusted anchors ($D_{\text{anchor}} \le 0.55$).
2. Mandatory human approval for anchor updates.

If operational teams configure TopoChain with automated anchor approvals without manual scrutiny, the anti-poisoning guarantee is voided. TopoChain is designed as a **decision-support and automated gating platform**, not a complete replacement for human code review.
