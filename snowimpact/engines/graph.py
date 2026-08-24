from __future__ import annotations

from collections import deque

import networkx as nx

from snowimpact.core.models import EnvironmentSnapshot, GraphEdge, GraphNode


class ImpactGraph:
    def __init__(self, snapshot: EnvironmentSnapshot):
        self.graph = nx.DiGraph()
        self.nodes_by_fqn: dict[str, str] = {}
        for node in snapshot.nodes:
            self.add_node(node)
        for edge in snapshot.edges:
            self.add_edge(edge)

    def add_node(self, node: GraphNode) -> None:
        self.graph.add_node(node.id, node_type=node.node_type, fqn=node.fqn, **node.attributes)
        self.nodes_by_fqn[node.fqn.upper()] = node.id

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source not in self.graph:
            self.graph.add_node(edge.source, node_type="UNKNOWN", fqn=edge.source)
        if edge.target not in self.graph:
            self.graph.add_node(edge.target, node_type="UNKNOWN", fqn=edge.target)
        self.graph.add_edge(edge.source, edge.target, edge_type=edge.edge_type, source_type=edge.source_type, confidence=edge.confidence, **edge.attributes)

    def resolve(self, fqn: str) -> str | None:
        direct = self.nodes_by_fqn.get(fqn.upper())
        if direct:
            return direct
        # For unqualified names, require a unique suffix match.
        suffix = f".{fqn.upper()}"
        matches = [node_id for key, node_id in self.nodes_by_fqn.items() if key == fqn.upper() or key.endswith(suffix)]
        return matches[0] if len(set(matches)) == 1 else None

    def downstream(self, fqn: str, max_depth: int = 20) -> list[dict[str, object]]:
        start = self.resolve(fqn)
        if not start:
            return []
        result: list[dict[str, object]] = []
        seen = {start}
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for nxt in self.graph.successors(current):
                if nxt in seen:
                    continue
                seen.add(nxt)
                attrs = self.graph.nodes[nxt]
                result.append({"id": nxt, "fqn": attrs.get("fqn", nxt), "node_type": attrs.get("node_type", "UNKNOWN"), "depth": depth + 1, "user": attrs.get("user")})
                queue.append((nxt, depth + 1))
        return result

    def shortest_path(self, source_fqn: str, target_fqn: str) -> list[str]:
        source = self.resolve(source_fqn)
        target = self.resolve(target_fqn)
        if not source or not target:
            return []
        try:
            return [str(self.graph.nodes[n].get("fqn", n)) for n in nx.shortest_path(self.graph, source, target)]
        except nx.NetworkXNoPath:
            return []
