"""
Base entity definitions and extraction result schemas for TopoChain.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any


class EntityType(str, Enum):
    FUNCTION = "FUNCTION"
    METHOD = "METHOD"
    CLASS = "CLASS"
    MODULE = "MODULE"
    CONTROL_BLOCK = "CONTROL_BLOCK"
    EXTERNAL_DEPENDENCY = "EXTERNAL_DEPENDENCY"
    SENSITIVE_HOOK = "SENSITIVE_HOOK"


@dataclass
class CodeEntity:
    id: str
    name: str
    entity_type: EntityType
    file_path: str
    line_start: int = 1
    line_end: int = 1
    complexity: int = 1  # Cyclomatic complexity
    calls: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    sensitive_operations: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DependencyEntity:
    name: str
    version_spec: str = "*"
    is_dev: bool = False
    is_direct: bool = True
    source_file: str = ""
    suspicious_flags: List[str] = field(default_factory=list)


@dataclass
class ExtractionResult:
    entities: Dict[str, CodeEntity] = field(default_factory=dict)
    dependencies: List[DependencyEntity] = field(default_factory=list)
    call_edges: List[Tuple[str, str, Dict[str, Any]]] = field(default_factory=list)
    files_scanned: List[str] = field(default_factory=list)
    language_stats: Dict[str, int] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {
            "total_entities": len(self.entities),
            "total_dependencies": len(self.dependencies),
            "total_edges": len(self.call_edges),
            "files_scanned_count": len(self.files_scanned),
            "languages": self.language_stats,
        }
