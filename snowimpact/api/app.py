from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from snowimpact import __version__
from snowimpact.api.deps import require_api_key
from snowimpact.collectors.demo import DemoCollector
from snowimpact.collectors.snowflake import SnowflakeCollector
from snowimpact.core.logging import configure_logging
from snowimpact.core.models import AnalysisRequest, AnalysisResult
from snowimpact.core.settings import get_settings
from snowimpact.core.telemetry import instrument_fastapi
from snowimpact.db.repository import Repository
from snowimpact.db.session import Database
from snowimpact.engines.analyzer import Analyzer
from snowimpact.integrations.github import GitHubAppClient

log = logging.getLogger(__name__)
settings = get_settings()
configure_logging(settings.log_level)

ANALYSIS_COUNTER = Counter("snowimpact_analyses_total", "Total analyses", ["decision"])
ANALYSIS_DURATION = Histogram("snowimpact_analysis_duration_seconds", "Analysis duration")


def build_analyzer() -> Analyzer:
    collector = DemoCollector() if settings.demo_mode else SnowflakeCollector(settings)
    return Analyzer(collector=collector)


db = Database(settings)
repository = Repository(db)
analyzer = build_analyzer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    problems = settings.validate_production_safety()
    if problems:
        raise RuntimeError("; ".join(problems))
    db.init()
    yield


app = FastAPI(
    title="SnowImpact API",
    version=__version__,
    description="Snowflake change intelligence and policy firewall",
    lifespan=lifespan,
)
instrument_fastapi(app, enabled=settings.telemetry)
cors_origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
if not cors_origins and not settings.is_production:
    cors_origins = ["http://localhost:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-SnowImpact-Key"],
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or hashlib.sha256(f"{time.time_ns()}:{request.url.path}".encode()).hexdigest()[:16]
    response = await call_next(request)
    response.headers["x-request-id"] = request_id
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["x-frame-options"] = "DENY"
    response.headers["referrer-policy"] = "no-referrer"
    return response


@app.exception_handler(ValueError)
async def value_error_handler(_request: Request, exc: ValueError):
    return JSONResponse(status_code=422, content={"error": {"code": "PARSER_ERROR", "message": str(exc), "recoverable": True}})


@app.get("/health")
def health():
    return {"status": "ok", "version": __version__}


@app.get("/ready")
def ready():
    return {"status": "ready", "demo_mode": settings.demo_mode}


@app.get("/metrics")
def metrics():
    return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/v1/capabilities", dependencies=[Depends(require_api_key)])
def capabilities():
    return analyzer.collector.doctor()


@app.post("/api/v1/analyses", response_model=AnalysisResult, dependencies=[Depends(require_api_key)])
def create_analysis(payload: AnalysisRequest):
    start = time.perf_counter()
    result = analyzer.analyze(payload)
    repository.save_analysis(payload, result)
    ANALYSIS_COUNTER.labels(decision=result.decision.value).inc()
    ANALYSIS_DURATION.observe(time.perf_counter() - start)
    return result


@app.get("/api/v1/analyses", dependencies=[Depends(require_api_key)])
def list_analyses(limit: int = 50):
    return repository.list_analyses(limit=min(max(limit, 1), 200))


@app.get("/api/v1/analyses/{analysis_id}", dependencies=[Depends(require_api_key)])
def get_analysis(analysis_id: str):
    result = repository.get_analysis(analysis_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result


def verify_github_signature(body: bytes, signature: str | None) -> bool:
    secret = settings.github_webhook_secret
    if not secret or not signature or not signature.startswith("sha256="):
        return False
    digest = hmac.new(secret.get_secret_value().encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={digest}", signature)


def _process_github_pull_request(payload: dict) -> None:
    try:
        action = str(payload.get("action") or "")
        if action not in {"opened", "reopened", "synchronize", "ready_for_review"}:
            return
        if not settings.github_app_id or not settings.github_private_key:
            log.error("GitHub webhook received but GitHub App credentials are not configured")
            return
        installation_id = int((payload.get("installation") or {}).get("id") or 0)
        repository_payload = payload.get("repository") or {}
        full_name = str(repository_payload.get("full_name") or "")
        pull = payload.get("pull_request") or {}
        pull_number = int(payload.get("number") or 0)
        head_sha = str((pull.get("head") or {}).get("sha") or "")
        if not installation_id or "/" not in full_name or not pull_number or not head_sha:
            raise ValueError("GitHub pull_request payload is missing installation/repository/PR/head data")

        owner, repo_name = full_name.split("/", 1)
        client = GitHubAppClient(
            settings.github_app_id,
            settings.github_private_key.get_secret_value(),
        )
        token = client.installation_token(installation_id)
        sql, paths = client.changed_sql(token, owner, repo_name, pull_number, head_sha)
        if not sql.strip():
            client.create_noop_check_run(token, owner, repo_name, head_sha)
            return

        result = analyzer.analyze(AnalysisRequest(
            sql=sql,
            filename=f"github:{full_name}#{pull_number}",
            repository=full_name,
            commit_sha=head_sha,
            environment="production",
        ))
        repository.save_analysis(
            AnalysisRequest(
                sql=sql,
                filename=f"github:{full_name}#{pull_number}",
                repository=full_name,
                commit_sha=head_sha,
                environment="production",
            ),
            result,
        )
        result_payload = result.model_dump(mode="json")
        result_payload.setdefault("metadata", {})["github_files"] = paths
        client.create_check_run(token, owner, repo_name, head_sha, result_payload)
    except Exception:
        log.exception("GitHub pull-request analysis failed")


@app.post("/api/v1/github/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    body = await request.body()
    if not verify_github_signature(body, request.headers.get("x-hub-signature-256")):
        raise HTTPException(status_code=401, detail="Invalid GitHub signature")
    event = request.headers.get("x-github-event", "")
    payload = json.loads(body or b"{}")
    if event == "pull_request":
        background_tasks.add_task(_process_github_pull_request, payload)
    return {"accepted": True, "event": event, "action": payload.get("action")}


@app.get("/api/v1/graph", dependencies=[Depends(require_api_key)])
def graph_snapshot():
    snapshot = analyzer.collector.collect("development" if settings.demo_mode else "production")
    return {"nodes": [n.model_dump(mode="json") for n in snapshot.nodes], "edges": [e.model_dump(mode="json") for e in snapshot.edges], "collected_at": snapshot.collected_at}


@app.get("/api/v1/security", dependencies=[Depends(require_api_key)])
def security_snapshot():
    snapshot = analyzer.collector.collect("development" if settings.demo_mode else "production")
    return {"privileges": snapshot.privileges, "classifications": snapshot.classifications, "capabilities": [c.model_dump(mode="json") for c in snapshot.capabilities]}


@app.get("/api/v1/costs", dependencies=[Depends(require_api_key)])
def cost_snapshot():
    snapshot = analyzer.collector.collect("development" if settings.demo_mode else "production")
    return {"warehouses": snapshot.warehouse_metrics, "query_metrics": snapshot.query_metrics}


@app.get("/api/v1/policies", dependencies=[Depends(require_api_key)])
def policies_snapshot():
    from snowimpact.engines.policy import PolicyEngine
    engine = PolicyEngine.from_directories(analyzer.policy_directories)
    return {"policies": [{"name": p.name, "category": p.category, "rules": p.rules, "severities": p.severities, "min_risk_score": p.min_risk_score, "action": p.action.value, "description": p.description} for p in engine.policies]}
