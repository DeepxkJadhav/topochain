"""
Extractor module for TopoChain.
"""

from topochain.core.extractor.base import (
    CodeEntity,
    DependencyEntity,
    EntityType,
    ExtractionResult,
)
from topochain.core.extractor.python_extractor import PythonASTExtractor
from topochain.core.extractor.js_extractor import JavaScriptExtractor
from topochain.core.extractor.dependency_extractor import DependencyExtractor
from topochain.core.extractor.codebase_extractor import CodebaseExtractor

__all__ = [
    "CodeEntity",
    "DependencyEntity",
    "EntityType",
    "ExtractionResult",
    "PythonASTExtractor",
    "JavaScriptExtractor",
    "DependencyExtractor",
    "CodebaseExtractor",
]
