"use client";

import { useEffect, useMemo, useState } from "react";
import { Background, Controls, Edge, Node, ReactFlow } from "@xyflow/react";
import { getGraph, GraphSnapshot } from "../lib/api";

export default function GraphExplorer() {
  const [snapshot, setSnapshot] = useState<GraphSnapshot>({ nodes: [], edges: [] });
  useEffect(() => { getGraph().then(setSnapshot); }, []);

  const nodes: Node[] = useMemo(() => snapshot.nodes.slice(0, 120).map((node, index) => ({
    id: node.id,
    position: { x: (index % 6) * 220, y: Math.floor(index / 6) * 110 },
    data: { label: `${node.node_type}\n${node.fqn}` },
    style: { width: 190, fontSize: 10, whiteSpace: "pre-line", borderRadius: 9, border: "1px solid #344150", background: "#111820", color: "#dbe5ee", padding: 8 },
  })), [snapshot]);
  const visible = useMemo(() => new Set(nodes.map(n => n.id)), [nodes]);
  const edges: Edge[] = useMemo(() => snapshot.edges.filter(e => visible.has(e.source) && visible.has(e.target)).slice(0, 240).map((edge, index) => ({
    id: `e-${index}-${edge.source}-${edge.target}`,
    source: edge.source,
    target: edge.target,
    label: edge.edge_type,
    labelStyle: { fontSize: 8 },
  })), [snapshot, visible]);

  return (
    <div className="graphWrap">
      {nodes.length === 0 ? <div className="empty">No graph metadata collected.</div> :
        <ReactFlow nodes={nodes} edges={edges} fitView nodesDraggable={false} minZoom={0.15} maxZoom={2}>
          <Background gap={20} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>}
    </div>
  );
}
