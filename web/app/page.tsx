"use client";

import { useEffect, useMemo, useState } from "react";
import { Analysis, analyzeSql, listAnalyses } from "../lib/api";
import GraphExplorer from "../components/GraphExplorer";

const demo = `ALTER TABLE PROD.CUSTOMER.CUSTOMERS DROP COLUMN REGION;
ALTER WAREHOUSE ANALYTICS_WH SET WAREHOUSE_SIZE='2XLARGE';
CREATE VIEW PROD.REPORTING.CUSTOMER_EXPORT AS SELECT * FROM PROD.CUSTOMER.CUSTOMERS;`;

function tone(value: string) {
  if (["block", "critical"].includes(value)) return "danger";
  if (["require_approval", "high"].includes(value)) return "warn";
  if (["warn", "medium"].includes(value)) return "medium";
  return "safe";
}

export default function Home() {
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [selected, setSelected] = useState<Analysis | null>(null);
  const [sql, setSql] = useState(demo);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => { listAnalyses().then((items) => { setAnalyses(items); if (items[0]) setSelected(items[0]); }); }, []);

  const stats = useMemo(() => {
    const source = selected || analyses[0];
    return source ? [
      ["Overall risk", `${source.risk.overall}/100`, tone(source.decision)],
      ["Findings", String(source.findings.length), source.findings.some(f => f.severity === "critical") ? "danger" : "medium"],
      ["Affected objects", String(source.affected_objects.length), "warn"],
      ["Coverage", `${source.coverage_percent}%`, source.coverage_percent >= 90 ? "safe" : "warn"],
    ] : [["Overall risk", "0/100", "safe"], ["Findings", "0", "safe"], ["Affected objects", "0", "safe"], ["Coverage", "100%", "safe"]];
  }, [selected, analyses]);

  async function run() {
    setBusy(true); setError("");
    try {
      const result = await analyzeSql(sql);
      setSelected(result);
      setAnalyses((old) => [result, ...old.filter(x => x.id !== result.id)]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed");
    } finally { setBusy(false); }
  }

  return (
    <div className="content">
      <header><div><p className="eyebrow">SNOWFLAKE CHANGE INTELLIGENCE</p><h1>Deployment risk, before production.</h1><p className="sub">Trace blast radius, privilege expansion, governance drift, FinOps impact, performance risk and agent exposure from one change.</p></div><div className="env">● Development</div></header>

      <section id="overview" className="stats">
        {stats.map(([label, value, cls]) => <div className="card" key={label}><span>{label}</span><strong className={String(cls)}>{value}</strong></div>)}
      </section>

      <section id="analysis" className="panel editorPanel">
        <div className="panelHead"><div><h2>Analyze Snowflake SQL</h2><p>Statements are parsed and simulated. They are never executed.</p></div><button onClick={run} disabled={busy}>{busy ? "Analyzing…" : "Run analysis"}</button></div>
        <textarea value={sql} onChange={e => setSql(e.target.value)} spellCheck={false} />
        {error && <div className="error">{error}</div>}
      </section>

      {selected && <>
        <section className="split">
          <div className="panel riskPanel">
            <div className="panelHead"><div><h2>Risk breakdown</h2><p>{selected.id}</p></div><span className={`pill ${tone(selected.decision)}`}>{selected.decision.replaceAll("_", " ")}</span></div>
            {Object.entries(selected.risk).filter(([k]) => k !== "overall").map(([k,v]) => <div className="barRow" key={k}><span>{k}</span><div className="bar"><i style={{width:`${v}%`}} /></div><b>{v}</b></div>)}
          </div>
          <div className="panel">
            <div className="panelHead"><div><h2>Blast radius</h2><p>Transitive impact and known principals</p></div></div>
            <div className="bigMetric">{selected.affected_objects.length}<small>objects affected</small></div>
            <div className="chips">{selected.affected_objects.slice(0,8).map(o => <span key={o}>{o}</span>)}</div>
          </div>
        </section>

        <section id="graph" className="panel">
          <div className="panelHead"><div><h2>Environment graph</h2><p>Read-only lineage and access relationships from the latest metadata snapshot</p></div></div>
          <GraphExplorer />
        </section>

        <section id="findings" className="panel">
          <div className="panelHead"><div><h2>Findings</h2><p>Deterministic evidence from the current snapshot and proposed diff</p></div></div>
          <div className="findings">
            {selected.findings.length === 0 && <div className="empty">No findings. Current policy decision is {selected.decision}.</div>}
            {selected.findings.map(f => <article key={f.id}><span className={`severity ${tone(f.severity)}`}>{f.severity}</span><div><h3>{f.title}</h3><p>{f.description}</p><code>{f.rule}</code></div><strong>{f.risk_score}</strong></article>)}
          </div>
        </section>
      </>}
    </div>
  );
}
