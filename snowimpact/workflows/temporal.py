from __future__ import annotations

import asyncio
from datetime import timedelta

from temporalio import activity, workflow

from snowimpact.collectors.demo import DemoCollector
from snowimpact.collectors.snowflake import SnowflakeCollector
from snowimpact.core.models import AnalysisRequest
from snowimpact.core.settings import get_settings
from snowimpact.engines.analyzer import Analyzer


@activity.defn
async def analyze_sql_activity(payload: dict) -> dict:
    request = AnalysisRequest.model_validate(payload)
    settings = get_settings()
    collector = DemoCollector() if settings.demo_mode else SnowflakeCollector(settings)
    result = await asyncio.to_thread(Analyzer(collector).analyze, request)
    return result.model_dump(mode="json")


@workflow.defn
class AnalysisWorkflow:
    @workflow.run
    async def run(self, payload: dict) -> dict:
        return await workflow.execute_activity(
            analyze_sql_activity,
            payload,
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=None,
        )
