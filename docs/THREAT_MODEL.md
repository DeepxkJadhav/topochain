# TopoChain Threat Model

## 1. Overview & System Scope
TopoChain is an automated defensive integrity verification platform designed to detect malicious alterations, unauthorized logic backdoors, dependency attacks, and slow behavioral drift in modern software supply chains.

This document specifies the adversarial threat environment, actor profiles, attack vectors, attack surfaces, and assumptions under which TopoChain operates.

---

## 2. Adversary Personas & Capabilities

| Adversary Profile | Motivations | Capabilities | Access Level |
|---|---|---|---|
| **Compromised Maintainer / Rogue Insider** | Direct backdoor injection, credential harvesting | Can commit directly to repositories, craft subtle commits, sign commits | Write access to repo source tree |
| **Credential Hijacker** | Supply chain hijacking, automated exfiltration | Compromised developer tokens / SSH keys; pushes code directly or opens PRs | Branch write or PR submission |
| **Dependency Typosquatter** | Mass automated harvesting of credentials | Publishes similarly named packages to public registries (PyPI, npm, crates.io) | External registry publication |
| **Dependency Confuser** | Enterprise perimeter bypass | Registers internal unscoped package names on public registries | External registry publication |
| **Adversarial ML Attacker** | Model poisoning, threshold manipulation | Pushes gradual micro-drifts over hundreds of commits to desensitize baseline | Multi-commit pull request capability |

---

## 3. Threat Vectors & Attack Classifications

TopoChain divides software supply chain attacks into two fundamental structural categories:

### A. Topology-Changing Attacks (Macroscopic Structural Mutations)
In these attacks, the adversary alters the codebase's connectivity, call graph, or dependency hierarchy:
1. **Malicious Package Injection & Typosquatting**:
   - Introducing typosquatted packages (e.g. `reqeusts` vs `requests`) or dependency confusion payloads.
2. **Untrusted Lifecycle Execution Hooks**:
   - Embedding arbitrary shell commands in `preinstall` or `postinstall` scripts in `package.json`.
3. **Execution Path Hijacking & Disconnected Call Loops**:
   - Creating new hidden functions, asynchronous threads, or covert exfiltration loops that alter high-dimensional Betti numbers ($H_0, H_1, H_2$).
4. **Obfuscated Payload Insertion**:
   - Injecting encoded blobs dynamically decoded via `eval` or `exec` in new isolated modules.

### B. Topology-Preserving Attacks (Microscopic / In-Place Tampering)
In these attacks, the adversary carefully modifies logic **without adding or removing functions, imports, modules, or call edges**:
1. **Conditional Authentication Bypass**:
   - Modifying an existing boolean condition inside an existing function:
     ```python
     # Original
     if not token or len(token) < 16:
         return False
     
     # Attacked (in-place)
     if token == 'root_backdoor_override' or not token:
         return True
     ```
   - *Topological impact*: Call graph $G$ and simplicial complex $K$ remain mathematically identical. Topological drift $\Delta = 0.0$.
2. **In-Place Credential Harvester**:
   - Reading environment variables (`os.environ['AWS_SECRET_ACCESS_KEY']`) inside an existing authentication routine.
3. **Subtle Cryptographic Weakening**:
   - Changing salt length, hash iterations, or key bit sizes in existing cryptographic methods.

> **Key Architectural Mandate**: TopoChain does **not** assume malicious code always creates a topological defect. In-place, topology-preserving attacks are detected by the **Semantic Analysis** and **Dependency Intelligence** channels.

---

## 4. Adversarial Baseline Poisoning (Slow-Drift Attacks)

A sophisticated adversary may attempt to poison the rolling baseline:
- An attacker introduces minor mutations over 50 consecutive commits, each producing a minute drift score $\Delta_t < 3\sigma$.
- In an unhardened system, rolling baseline mean $\mu$ and variance $\sigma^2$ gradually expand, accommodating the malicious state.

### Mitigation in TopoChain:
1. **Immutable Trusted Anchor**: Every project maintains a cryptographic anchor $A_0$ approved by human security leads.
2. **Cumulative Anchor Drift Boundary**: In addition to step drift $\Delta = \|\mathbf{z}_t - \mathbf{z}_{t-1}\|_2$, TopoChain enforces cumulative distance $D_{\text{anchor}} = \|\mathbf{z}_t - \mathbf{z}_{\text{anchor}}\|_2 \le 0.55$.
3. **Explicit Trust Approval Gate**: Baseline updates require manual promotion via `topochain baseline approve <commit>`.

---

## 5. System Boundary & Out-of-Scope Risks

The following attack vectors are outside TopoChain's core verification boundary:
1. **Host Kernel Exploits**: Kernel vulnerabilities compromising the host operating system directly.
2. **Compiler / Toolchain Subversion**: Attacks mutating the compiler binary (e.g. Ken Thompson's *Reflections on Trusting Trust*).
3. **Hardware-Level Side Channels**: Rowhammer, Spectre, Meltdown attacking memory directly during execution.
