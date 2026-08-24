export type Finding = {
  id: string;
  severity: string;
  category: string;
  rule: string;
  title: string;
  description: string;
  risk_score: number;
  affected_objects: string[];
};

export type Analysis = {
  id: string;
  decision: string;
  coverage_percent: number;
  risk: { overall: number; security: number; governance: number; dependencies: number; finops: number; performance: number; ai: number };
  findings: Finding[];
  changes: Array<{ operation: string; object: { object_type: string; name: string; column?: string; database?: string; schema?: string } }>;
  affected_objects: string[];
  affected_users: string[];
  missing_capabilities: string[];
};

export async function listAnalyses(): Promise<Analysis[]> {
  const response = await fetch(`/api/snowimpact/analyses`, { cache: "no-store" });
  if (!response.ok) return [];
  return response.json();
}

export async function analyzeSql(sql: string): Promise<Analysis> {
  const response = await fetch(`/api/snowimpact/analyses`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({sql, filename: "dashboard.sql", environment: "development"})
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

export type GraphSnapshot = {
  nodes: Array<{ id: string; node_type: string; fqn: string; attributes: Record<string, unknown> }>;
  edges: Array<{ source: string; target: string; edge_type: string; confidence: number }>;
};

export async function getGraph(): Promise<GraphSnapshot> {
  const response = await fetch(`/api/snowimpact/graph`, { cache: "no-store" });
  if (!response.ok) return { nodes: [], edges: [] };
  return response.json();
}
