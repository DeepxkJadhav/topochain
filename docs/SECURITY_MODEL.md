# TopoChain Security Model & Architecture

## 1. Core Security Principles

TopoChain adheres to four defensive engineering axioms:

1. **Zero Trust for Codebase Content**: Every source file, package manifest, script, and git commit is treated as potentially adversarial input.
2. **Zero Host Execution of Untrusted Code**: TopoChain **never** executes repository-controlled scripts or binaries directly on the host machine. Runtime observation is conducted solely via safe static capability emulation or ephemeral, network-isolated container sandboxes.
3. **Independent Multimodal Verification**: No single security signal has unilateral veto or approval power. Topological drift is paired with semantic analysis, dependency intelligence, and git dynamics.
4. **Defensible Governance & Auditability**: All baseline updates, model parameters, and anchor changes require explicit cryptographic tracking and human sign-off.

---

## 2. Multi-Layer Defense Architecture

```text
               INCOMING COMMIT
                     │
    ┌────────────────┼────────────────┐
    ▼                ▼                ▼
[Code Structure] [Dependencies]   [Git History]
(AST/CFG Graph) (Multi-Ecosystem) (Entropy/Churn)
    │                │                │
    ├────────────────┴────────────────┘
    │
    ▼
[Topological Manifold Analysis]
(Vietoris-Rips Filtration + Persistent Homology H0, H1, H2)
    │
    ▼
[Semantic Capability Analysis]
(Exfiltration Chains, Auth Bypasses, Dangerous Sinks)
    │
    ▼
[Isolated Behavioral Sandbox] (Optional)
(Static Capability Emulation / Ephemeral Network-Isolated Container)
    │
    ▼
[Multimodal Risk Fusion Engine]
(Synergy Boosting, Dynamic Channel Weighting, Refactor Suppression)
    │
    ▼
[Defensible Decision Engine]
  ┌──────────┼──────────┐
  ▼          ▼          ▼
 SAFE      REVIEW     BLOCK
 (0)        (0)        (1)
```

---

## 3. Subsystem Specifications

### 3.1. Multi-Ecosystem Dependency Intelligence
- **Supported Ecosystems**: Python (`requirements.txt`, `pyproject.toml`, `poetry.lock`), JavaScript/TypeScript (`package.json`, `package-lock.json`), Go (`go.mod`), Rust (`Cargo.toml`, `Cargo.lock`).
- **Detection Capabilities**:
  - Damerau-Levenshtein distance calculation against top open-source registries (e.g. `reqeusts` vs `requests`).
  - Leetspeak substitution matching (`0` $\to$ `o`, `1` $\to$ `l`, `3` $\to$ `e`).
  - Dependency confusion matching against un-scoped internal corporate namespaces.
  - Untrusted lifecycle hooks (`preinstall`, `postinstall`, `prepare`) containing shell commands (`curl`, `bash`, `powershell`).

### 3.2. Semantic Capability Analysis
- **Static AST-Driven Capability Extraction**:
  - `DYNAMIC_EXECUTION`: `eval`, `exec`, `__import__`, `Function` constructor.
  - `SUBPROCESS_SPAWN`: `subprocess.Popen`, `child_process.exec`, `os.system`.
  - `NETWORK_DISPATCH`: `socket`, `requests`, `urllib`, `fetch`, `http.Client`.
  - `CREDENTIAL_ACCESS`: accessing AWS keys, private tokens, passwords, `.env`.
  - `AUTHENTICATION_BYPASS`: constant conditional bypasses (`root_backdoor_override`).
- **Multi-Capability Correlation**: Identifies exfiltration patterns when network dispatch co-occurs with credential harvesting.

### 3.3. Isolated Behavioral Sandbox
- **Safe Emulation Mode (Default)**: Statically traces runtime event signatures and package lifecycle scripts without executing code.
- **Container Mode**: When Docker/Podman is configured, runs an isolated ephemeral container with:
  - `--network none` (complete outbound network block)
  - `--read-only` root filesystem
  - Non-root user privileges
  - Strict memory limit (`256m`) and 15-second hard execution timeout.

---

## 4. Baseline Protection & Anti-Poisoning Architecture

### 4.1. SQLite Persistence Security Schema
```sql
CREATE TABLE IF NOT EXISTS trusted_anchors (
    project_id TEXT PRIMARY KEY,
    anchor_commit TEXT,
    anchor_embedding BLOB,
    approved_by TEXT,
    created_at TIMESTAMP,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);

CREATE TABLE IF NOT EXISTS baseline_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT,
    commit_hash TEXT,
    drift_mean REAL,
    drift_variance REAL,
    sample_count INTEGER,
    approved_by TEXT,
    reason TEXT,
    updated_at TIMESTAMP
);
```

### 4.2. Dual-Distance Drift Verification
For any candidate commit $t$, TopoChain computes:
1. **Step Drift**: $\Delta_t = \|\mathbf{z}_t - \mathbf{z}_{t-1}\|_2$.
2. **Cumulative Anchor Drift**: $D_{\text{anchor}} = \|\mathbf{z}_t - \mathbf{z}_{\text{anchor}}\|_2$.

If $D_{\text{anchor}} > 0.55$, TopoChain flags an immediate **Drift Poisoning Alert** and suppresses automated baseline updates, forcing human review.

---

## 5. Self-Security & Hardening Guardrails

| Threat to TopoChain | Hardening Implementation |
|---|---|
| **Path Traversal Escape** | All paths validated via `Path.resolve().relative_to(repo_path)`; external symlinks dropped. |
| **Algorithmic Complexity DoS** | Maximum node cap $N \le 400$ in `GraphBuilder`; prunes lower-degree nodes before Dijkstra. |
| **TDA Combinatorial Explosion** | Vietoris-Rips filtration restricted to max homology dimension $k = 2$ ($H_0, H_1, H_2$). |
| **Malformed / Corrupted Syntax** | AST parsers wrap file parsing in isolated `try/except` blocks; invalid files recorded without pipeline termination. |
| **JSON Serialization Exploits** | Recursive sanitization converts `NaN`, `±Inf` and raw NumPy arrays to compliant standard primitives. |
