# Authors & Open-Source Attribution

## Primary Author & Lead Architect
- **Deepak Jadhav** ([@DeepxkJadhav](https://github.com/DeepxkJadhav))
  - Conceptual design, system architecture, and multimodal drift fusion pipeline
  - AST code graph extraction & dependency intelligence subsystem
  - Topological drift detector and Wasserstein distance computation
  - Synthetic attack evaluation harness and empirical ablation benchmark suite

---

## Academic & Open-Source Foundations

TopoChain builds upon seminal research in algebraic topology, topological data analysis (TDA), and compiler theory. We gratefully acknowledge the following core algorithms and upstream libraries:

1. **Ripser** (`ripser`)  
   *Ulrich Bauer et al.* — High-performance computation of Vietoris-Rips persistent homology using coboundary matrix reduction and apparent pairs.
2. **Persim** (`persim`)  
   *Scikit-TDA Team* — Persistence diagram vectorization, Bottleneck distance, and Wasserstein metric algorithms.
3. **Tree-Sitter** (`tree-sitter`, `tree-sitter-languages`)  
   *Max Brunsfeld et al.* — Incremental, multi-language concrete syntax tree (CST) parsing framework.
4. **NetworkX** (`networkx`)  
   *Aric Hagberg, Dan Schult, Pieter Swart* — Graph and network analysis structures and shortest-path metric spaces.
5. **PyTorch** (`torch`)  
   *Meta AI / PyTorch Foundation* — Tensor computational graph execution for Topological Neural Networks (TNN).
