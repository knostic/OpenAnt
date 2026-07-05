"""
Agentic Context Enhancer

Iteratively explores codebase using LLM with tool use to gather
context for security analysis. Unlike single-shot analysis, this
approach traces call paths and understands code intent.

Supports reachability-aware classification:
- EXPLOITABLE: Vulnerable + reachable from user input
- VULNERABLE_INTERNAL: Vulnerable but not user-reachable
- SECURITY_CONTROL: Defensive code
- NEUTRAL: No security relevance
"""

from .agent import (
    ContextAgent,
    AgentResult,
    enhance_unit_with_agent,
    create_reachability_context
)
from .repository_index import RepositoryIndex, load_index_from_file
from .tools import TOOL_DEFINITIONS, ToolExecutor
from .entry_point_detector import EntryPointDetector, blackout_warning, library_seed_ids
from .reachability_analyzer import ReachabilityAnalyzer

__all__ = [
    "ContextAgent",
    "AgentResult",
    "enhance_unit_with_agent",
    "create_reachability_context",
    "RepositoryIndex",
    "load_index_from_file",
    "TOOL_DEFINITIONS",
    "ToolExecutor",
    "EntryPointDetector",
    "blackout_warning",
    "library_seed_ids",
    "ReachabilityAnalyzer"
]
