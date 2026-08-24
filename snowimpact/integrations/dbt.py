from __future__ import annotations

import json
from pathlib import Path

from snowimpact.core.models import GraphEdge, GraphNode


def parse_dbt_manifest(path: str | Path) -> tuple[list[GraphNode], list[GraphEdge]]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    by_unique: dict[str, str] = {}
    for section in ("nodes", "sources"):
        for unique_id, item in raw.get(section, {}).items():
            relation = item.get("relation_name") or ".".join(filter(None, [item.get("database"), item.get("schema"), item.get("alias") or item.get("name")]))
            node_id = f"dbt:{unique_id}"
            by_unique[unique_id] = node_id
            nodes.append(GraphNode(id=node_id, node_type="DBT_MODEL" if section == "nodes" else "DBT_SOURCE", fqn=relation or unique_id, attributes={"unique_id": unique_id, "owner": item.get("meta", {}).get("owner")}))
    for unique_id, item in raw.get("nodes", {}).items():
        target = by_unique.get(unique_id)
        if not target:
            continue
        for dep in item.get("depends_on", {}).get("nodes", []):
            source = by_unique.get(dep)
            if source:
                edges.append(GraphEdge(source=source, target=target, edge_type="DEPENDS_ON", source_type="dbt_manifest", confidence=1.0))
    return nodes, edges
