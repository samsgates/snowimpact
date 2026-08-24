from __future__ import annotations

import asyncio
import os

from temporalio.client import Client
from temporalio.worker import Worker

from snowimpact.workflows.temporal import AnalysisWorkflow, analyze_sql_activity


async def main() -> None:
    target = os.getenv("TEMPORAL_ADDRESS", "localhost:7233")
    client = await Client.connect(target)
    worker = Worker(client, task_queue="snowimpact-analysis", workflows=[AnalysisWorkflow], activities=[analyze_sql_activity])
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
