"""
Visualization and ASCII summary tools for persistence diagrams and images.
"""

from pathlib import Path
from typing import Optional, Dict, Any
import numpy as np

from topochain.core.topology.homology import PersistenceDiagramSet


class TopologicalVisualizer:
    """
    Renders topological persistence features as ASCII barcodes or plots.
    """

    @staticmethod
    def format_ascii_summary(diagrams: PersistenceDiagramSet) -> str:
        lines = []
        lines.append("  ┌── Persistent Homology Invariants ──────────────────────┐")
        lines.append(f"  │ H_0 (Connected Components) : {len(diagrams.h0):<4} (Betti_0: {diagrams.betti_numbers.get('b0', 0):<2}) │")
        lines.append(f"  │ H_1 (Topological Loops)    : {len(diagrams.h1):<4} (Betti_1: {diagrams.betti_numbers.get('b1', 0):<2}) │")
        lines.append(f"  │ H_2 (Topological Voids)    : {len(diagrams.h2):<4} (Betti_2: {diagrams.betti_numbers.get('b2', 0):<2}) │")
        lines.append("  ├────────────────────────────────────────────────────────┤")
        lines.append(f"  │ Total Persistence H_1      : {diagrams.total_persistence.get('h1', 0.0):.4f}{'':<14} │")
        lines.append(f"  │ Persistent Entropy H_1     : {diagrams.persistent_entropy.get('h1', 0.0):.4f}{'':<14} │")
        lines.append("  └────────────────────────────────────────────────────────┘")

        # Add mini barcode representation for H_1 loops
        if len(diagrams.h1) > 0:
            lines.append("  H_1 Persistence Loops Barcode:")
            sorted_h1 = sorted(diagrams.h1, key=lambda p: p[1] - p[0], reverse=True)[:5]
            for idx, pt in enumerate(sorted_h1):
                b, d = pt[0], pt[1]
                start_col = int(min(25, max(0, b * 25)))
                bar_len = int(min(25, max(1, (d - b) * 25)))
                bar_str = " " * start_col + "█" * bar_len
                lines.append(f"    Loop #{idx+1} [{b:.2f} -> {d:.2f}] : {bar_str}")

        return "\n".join(lines)

    @staticmethod
    def save_plot(
        diagrams: PersistenceDiagramSet,
        image_tensor: np.ndarray,
        output_path: str,
        title: str = "TopoChain Topological State"
    ) -> str:
        """
        Saves a matplotlib visualization of persistence diagrams and multi-channel persistence images.
        """
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, axes = plt.subplots(2, 3, figsize=(15, 9))
        fig.suptitle(title, fontsize=14, fontweight="bold")

        # Row 1: Persistence Diagrams
        d_titles = ["H_0 Connected Components", "H_1 Loops (Call Cycles)", "H_2 Voids (High-Order Cliques)"]
        d_data = [diagrams.h0, diagrams.h1, diagrams.h2]
        colors = ["#2b5c8f", "#d95f02", "#7570b3"]

        for col, (ax, dgm, dt, c) in enumerate(zip(axes[0], d_data, d_titles, colors)):
            ax.set_title(dt, fontsize=11)
            ax.plot([0, 1], [0, 1], linestyle="--", color="gray", alpha=0.6)
            if len(dgm) > 0:
                finite = dgm.copy()
                finite[np.isinf(finite[:, 1]), 1] = 1.0
                ax.scatter(finite[:, 0], finite[:, 1], c=c, alpha=0.8, edgecolors="none", s=30)
            ax.set_xlim(-0.05, 1.05)
            ax.set_ylim(-0.05, 1.05)
            ax.set_xlabel("Birth")
            ax.set_ylabel("Death")
            ax.grid(True, linestyle=":", alpha=0.5)

        # Row 2: Persistence Images (Channels 0, 1, 2)
        im_titles = ["H_0 Persistence Heatmap", "H_1 Persistence Heatmap", "H_2 Persistence Heatmap"]
        cmaps = ["Blues", "Oranges", "Purples"]

        for col, (ax, chan, it, cm) in enumerate(zip(axes[1], image_tensor, im_titles, cmaps)):
            ax.set_title(it, fontsize=11)
            im = ax.imshow(chan, origin="lower", extent=[0, 1, 0, 1], cmap=cm, aspect="auto")
            fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
            ax.set_xlabel("Birth")
            ax.set_ylabel("Persistence (Death - Birth)")

        plt.tight_layout()
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(str(out), dpi=150)
        plt.close(fig)
        return str(out)
