from __future__ import annotations

from snowimpact.core.models import AnalysisRequest, AnalysisResult
from snowimpact.db.models import AnalysisRecord, AuditEvent
from snowimpact.db.session import Database


class Repository:
    def __init__(self, db: Database):
        self.db = db

    def save_analysis(self, request: AnalysisRequest, result: AnalysisResult) -> None:
        with self.db.session() as session:
            session.merge(AnalysisRecord(
                id=result.id,
                environment=request.environment,
                status=result.status.value,
                decision=result.decision.value,
                risk_score=result.risk.overall,
                request_json=request.model_dump(mode="json"),
                result_json=result.model_dump(mode="json"),
            ))
            session.add(AuditEvent(action="analysis.completed", resource=result.id, detail={"decision": result.decision.value, "risk": result.risk.overall}))

    def get_analysis(self, analysis_id: str) -> dict | None:
        with self.db.session() as session:
            row = session.get(AnalysisRecord, analysis_id)
            return row.result_json if row else None

    def list_analyses(self, limit: int = 50) -> list[dict]:
        from sqlalchemy import select
        with self.db.session() as session:
            rows = session.scalars(select(AnalysisRecord).order_by(AnalysisRecord.created_at.desc()).limit(limit)).all()
            return [r.result_json for r in rows]
