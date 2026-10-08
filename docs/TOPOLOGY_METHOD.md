# Topological Method & Mathematical Foundations

## 1. Introduction & Mathematical Motivation

Software systems are complex relational networks consisting of abstract syntax trees, function call graphs, module hierarchies, and external dependency manifests. Traditional static analysis tools represent software as flat syntax trees or signature dictionaries.

TopoChain leverages **Algebraic Topology**—specifically **Persistent Homology** on simplicial complexes—to model software architecture as a high-dimensional geometric manifold. This captures the intrinsic *shape* of code execution paths, loops, and clusters independently of variable renaming, comment alterations, or superficial syntactic refactoring.

---

## 2. Codebase Metric Space Construction

### 2.1. Software Graph Extraction
A codebase snapshot is extracted into a directed graph $G = (V, E)$, where:
- $V$: Extracted code entities (functions, methods, classes, modules, external packages).
- $E$: Directed relations (call invocations, class inheritances, package imports).

### 2.2. Metric Weighting & Distance Matrix
For each edge $e = (u, v) \in E$, a metric weight $w(e) \in (0, 1]$ is assigned based on cognitive complexity $c(u)$, target complexity $c(v)$, and privilege-sensitive operations:
$$w(e) = \frac{1}{1 + \ln(1 + c(u) \cdot c(v))} \cdot \left(1 - 0.2 \cdot \mathbb{I}_{\text{sensitive}}(u, v)\right)$$

The metric space $(V, d_G)$ is established via the all-pairs shortest path geodesic distance:
$$d_G(u, v) = \min_{p \in \mathcal{P}(u, v)} \sum_{e \in p} w(e)$$
For disconnected components, a maximum boundary distance $d_{\max} = 1.0$ is applied, yielding a symmetric distance matrix $\mathbf{D} \in \mathbb{R}^{|V| \times |V|}$.

---

## 3. Simplicial Complex Filtration & Persistent Homology

### 3.1. Vietoris-Rips Complex
From the metric space $(V, d_G)$ and a filtration parameter $\epsilon \ge 0$, the Vietoris-Rips complex $\text{VR}(G, \epsilon)$ is defined as the abstract simplicial complex:
$$\text{VR}(G, \epsilon) = \left\{ \sigma \subseteq V \;\middle|\; \forall u, v \in \sigma,\; d_G(u, v) \le \epsilon \right\}$$
A $k$-simplex $\sigma = [v_0, v_1, \dots, v_k]$ is formed whenever all pairwise distances between its $k+1$ vertices are at most $\epsilon$.

As $\epsilon$ increases from $0$ to $d_{\max}$, a nested filtration sequence is generated:
$$\emptyset = K_0 \subseteq K_{\epsilon_1} \subseteq K_{\epsilon_2} \subseteq \dots \subseteq K_{\epsilon_{\max}} = K$$

### 3.2. Homology Groups
For each dimension $k \ge 0$, chain groups $C_k(K_\epsilon)$ are vector spaces over $\mathbb{Z}_2$. The boundary operator $\partial_k: C_k \to C_{k-1}$ satisfies:
$$\partial_{k-1} \circ \partial_k = 0$$

The $k$-th homology vector space $H_k(K_\epsilon)$ captures topological features:
$$H_k(K_\epsilon) = \frac{Z_k(K_\epsilon)}{B_k(K_\epsilon)} = \frac{\ker(\partial_k)}{\text{im}(\partial_{k+1})}$$
- **$H_0$ (0-dimensional)**: Connected components / isolated clusters.
- **$H_1$ (1-dimensional)**: 1-dimensional cycles / call loops / dependency cycles.
- **$H_2$ (2-dimensional)**: 2-dimensional voids / complex multi-module interactions.

### 3.3. Persistence Diagrams
Each topological feature $i$ in dimension $k$ appears at birth parameter $b_i$ and merges/vanishes at death parameter $d_i$. The set of pairs forms the persistence diagram:
$$\text{Dgm}_k = \left\{ (b_i, d_i) \in \mathbb{R}^2 \;\middle|\; b_i < d_i \right\}$$
The persistence (lifetime) of feature $i$ is $\ell_i = d_i - b_i$. Long-lived features represent robust structural invariants of the architecture; short-lived features represent transient syntactic noise.

---

## 4. Vectorization & Latent Manifold Embedding

### 4.1. Persistence Image Transformation
To convert multi-scale persistence diagrams into inputs suitable for neural and statistical models, TopoChain uses a weighted Gaussian surface transform (Adams et al.):
$$\rho_k(x, y) = \sum_{(b, d) \in \text{Dgm}_k} w(b, d) \cdot \frac{1}{2\pi \sigma^2} \exp\left( -\frac{(x - b)^2 + (y - (d - b))^2}{2\sigma^2} \right)$$
where $w(b, d) = \arctan\left( C (d - b)^p \right)$ emphasizes persistent topological invariants.

Discretizing $\rho_k$ onto a $32 \times 32$ grid yields an image tensor $\mathbf{X} \in \mathbb{R}^{3 \times 32 \times 32}$ spanning $H_0, H_1, H_2$.

### 4.2. Topological Neural Network (TNN) Embedding
A lightweight Topological Convolutional Network projects $\mathbf{X}$ to a normalized latent unit hypersphere:
$$\mathbf{z}_t = \frac{f_\theta(\mathbf{X}_t)}{\|f_\theta(\mathbf{X}_t)\|_2} \in \mathbb{S}^{d-1} \subset \mathbb{R}^{64}$$

---

## 5. Topological Drift & Statistical Anomaly Detection

### 5.1. Scalar Step Drift
Between consecutive commits $t-1$ and $t$, the scalar topological drift is the Euclidean distance between their normalized embeddings:
$$\Delta_t = \|\mathbf{z}_t - \mathbf{z}_{t-1}\|_2 \in [0, 2]$$

### 5.2. Running Statistical Distribution
TopoChain maintains Welford's online running moments for the scalar drift distribution:
$$\mu_{\Delta, t} = \mu_{\Delta, t-1} + \frac{\Delta_t - \mu_{\Delta, t-1}}{N_t}$$
$$M_{2, t} = M_{2, t-1} + (\Delta_t - \mu_{\Delta, t-1})(\Delta_t - \mu_{\Delta, t})$$
$$\sigma_{\Delta, t}^2 = \frac{M_{2, t}}{N_t - 1}$$

The anomaly $z$-score is computed with safe numerical regularization:
$$z_t = \frac{\Delta_t - \mu_\Delta}{\sqrt{\sigma_\Delta^2 + \epsilon_{\text{safe}}}}, \quad \epsilon_{\text{safe}} = 10^{-8}$$

---

## 6. Theoretical Boundaries: Why Topology Cannot Stand Alone

While persistent homology provides deep geometric invariants, it is subject to fundamental algebraic boundaries:

1. **Invariance to Internal Logic Changes (Topology-Preserving Attacks)**:
   If an adversary alters a conditional check (`if token == "override"`) or steals credentials within an existing function, the graph nodes $V$ and edges $E$ remain identical:
   $$G_{t} \cong G_{t-1} \implies \text{Dgm}(G_t) = \text{Dgm}(G_{t-1}) \implies \Delta_t = 0.0$$
   *Topological analysis alone is completely blind to in-place logic backdoors.*

2. **Sensitivity to Legitimate Refactoring**:
   Splitting a monolithic module into multiple helper functions or extracting a class creates new nodes, edges, and cycles, resulting in non-zero topological drift ($\Delta_t > 0.35$).
   *Topological analysis alone will flag legitimate architectural refactorings as false positives.*

**Conclusion**: Topological Drift must function as **one component within a multimodal fusion engine**, corroborated by **Dependency Intelligence** and **Semantic Capability Analysis**.
