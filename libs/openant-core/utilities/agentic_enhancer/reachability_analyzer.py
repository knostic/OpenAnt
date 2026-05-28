"""
Reachability Analyzer

Determines if functions are reachable from entry points using the reverse call graph.
This enables filtering vulnerable code based on whether user input can reach it.

A function is "reachable" if there exists a call path from any entry point to that
function. The path is traced backwards: starting from the target function, we follow
the reverse call graph (who calls this?) until we reach an entry point or exhaust
the search.

Example:
    Entry point: handle_request()
    Call chain: handle_request() -> process_data() -> unsafe_eval()

    unsafe_eval() is reachable from handle_request() via process_data()

Usage:
    analyzer = ReachabilityAnalyzer(functions, reverse_call_graph, entry_points)

    if analyzer.is_reachable_from_entry_point('file.py:unsafe_eval'):
        print("Exploitable!")
        path = analyzer.get_entry_point_path('file.py:unsafe_eval')
        print(f"Path: {' -> '.join(path)}")
"""

from typing import Dict, List, Optional, Set, Tuple


class ReachabilityAnalyzer:
    """
    Analyzes whether functions are reachable from entry points.

    Uses BFS on the reverse call graph to find paths from entry points
    to target functions. Results are cached for efficiency.

    Attributes:
        functions: Dict of func_id -> func_data
        reverse_call_graph: Dict of func_id -> [caller_func_ids]
        entry_points: Set of func_ids that are entry points
        max_depth: Maximum depth to search (prevents infinite loops)
    """

    def __init__(
        self,
        functions: Dict,
        reverse_call_graph: Dict,
        entry_points: Set[str],
        max_depth: int = 15
    ):
        """
        Initialize the analyzer.

        Args:
            functions: Dict mapping func_id to function metadata
            reverse_call_graph: Dict mapping func_id to list of callers
            entry_points: Set of func_ids that are entry points
            max_depth: Maximum search depth (default 15)
        """
        self.functions = functions
        self.reverse_call_graph = reverse_call_graph
        self.entry_points = entry_points
        self.max_depth = max_depth

        # Cache reachability results
        self._reachability_cache: Dict[str, bool] = {}
        self._entry_point_path: Dict[str, List[str]] = {}
        self._reaching_entry_point: Dict[str, str] = {}

    def is_reachable_from_entry_point(self, func_id: str) -> bool:
        """
        Check if func_id is reachable from any entry point.

        Args:
            func_id: Function identifier to check

        Returns:
            True if reachable from any entry point, False otherwise
        """
        # Check cache first
        if func_id in self._reachability_cache:
            return self._reachability_cache[func_id]

        # Entry points are trivially reachable
        if func_id in self.entry_points:
            self._reachability_cache[func_id] = True
            self._entry_point_path[func_id] = [func_id]
            self._reaching_entry_point[func_id] = func_id
            return True

        # BFS backwards through reverse call graph
        visited: Set[str] = {func_id}
        # Queue: (current_func_id, path_from_target, depth)
        queue: List[Tuple[str, List[str], int]] = [(func_id, [func_id], 0)]

        while queue:
            current_id, path, depth = queue.pop(0)

            if depth >= self.max_depth:
                continue

            callers = self.reverse_call_graph.get(current_id, [])
            for caller_id in callers:
                if caller_id in self.entry_points:
                    # Found path to entry point
                    # Path is from target to entry point, reverse for intuitive order
                    full_path = list(reversed(path + [caller_id]))
                    self._reachability_cache[func_id] = True
                    self._entry_point_path[func_id] = full_path
                    self._reaching_entry_point[func_id] = caller_id
                    return True

                if caller_id not in visited:
                    visited.add(caller_id)
                    queue.append((caller_id, path + [caller_id], depth + 1))

        # No path found
        self._reachability_cache[func_id] = False
        return False

    def get_entry_point_path(self, func_id: str) -> List[str]:
        """
        Get the call path from entry point to func_id.

        The path is ordered from entry point to target:
        [entry_point, ..., intermediate_funcs, ..., func_id]

        Args:
            func_id: Target function identifier

        Returns:
            List of func_ids forming the path, or empty if not reachable
        """
        # Ensure reachability has been computed
        if func_id not in self._reachability_cache:
            self.is_reachable_from_entry_point(func_id)

        return self._entry_point_path.get(func_id, [])

    def get_reaching_entry_point(self, func_id: str) -> Optional[str]:
        """
        Get the entry point that can reach func_id.

        Args:
            func_id: Target function identifier

        Returns:
            func_id of the entry point, or None if not reachable
        """
        if func_id not in self._reachability_cache:
            self.is_reachable_from_entry_point(func_id)

        return self._reaching_entry_point.get(func_id)

    def get_all_reachable(self) -> Set[str]:
        """
        Get all functions reachable from any entry point.

        This is more efficient than calling is_reachable_from_entry_point()
        for each function individually, as it uses forward propagation.

        Returns:
            Set of func_ids reachable from entry points
        """
        reachable: Set[str] = set(self.entry_points)

        # Build forward call graph from reverse
        forward_graph: Dict[str, List[str]] = {}
        for callee, callers in self.reverse_call_graph.items():
            for caller in callers:
                if caller not in forward_graph:
                    forward_graph[caller] = []
                forward_graph[caller].append(callee)

        # BFS forward from all entry points
        queue = list(self.entry_points)
        visited = set(self.entry_points)

        while queue:
            current = queue.pop(0)
            callees = forward_graph.get(current, [])
            for callee in callees:
                if callee not in visited:
                    visited.add(callee)
                    reachable.add(callee)
                    queue.append(callee)

        # Update cache. get_all_reachable() is the AUTHORITATIVE result -- an UNBOUNDED forward BFS over
        # the full graph. is_reachable_from_entry_point() is a depth-BOUNDED reverse BFS that caches
        # False for functions farther than max_depth from an entry point (a false negative). Overwrite
        # unconditionally (the old "only if absent" froze whichever pass ran first) so this complete
        # pass corrects any stale bounded result. The forward graph is built from the same reverse
        # edges, so this can only flip stale False->True, never introduce a false positive.
        for func_id in self.functions:
            self._reachability_cache[func_id] = func_id in reachable

        return reachable

    def get_unreachable(self) -> Set[str]:
        """
        Get all functions NOT reachable from any entry point.

        Returns:
            Set of func_ids not reachable from entry points
        """
        reachable = self.get_all_reachable()
        return set(self.functions.keys()) - reachable

    def get_statistics(self) -> Dict:
        """
        Get statistics about reachability analysis.

        Returns:
            Dict with reachability statistics
        """
        reachable = self.get_all_reachable()
        total = len(self.functions)

        return {
            'total_functions': total,
            'entry_points': len(self.entry_points),
            'reachable': len(reachable),
            'unreachable': total - len(reachable),
            'reachable_percentage': round(
                len(reachable) / total * 100, 1
            ) if total > 0 else 0,
            'max_depth': self.max_depth,
        }

    def get_reachability_summary(self, func_id: str) -> Dict:
        """
        Get a summary of reachability for a specific function.

        Args:
            func_id: Function identifier

        Returns:
            Dict with reachability details
        """
        is_reachable = self.is_reachable_from_entry_point(func_id)

        return {
            'func_id': func_id,
            'is_entry_point': func_id in self.entry_points,
            'is_reachable': is_reachable,
            'entry_point': self.get_reaching_entry_point(func_id),
            'path': self.get_entry_point_path(func_id),
            'path_length': len(self.get_entry_point_path(func_id)),
        }
