from __future__ import annotations

import logging

from fastapi import FastAPI

log = logging.getLogger(__name__)


def instrument_fastapi(app: FastAPI, *, enabled: bool) -> bool:
    """Enable OpenTelemetry FastAPI instrumentation when the optional extra is installed.

    Exporter selection and credentials are intentionally left to standard OpenTelemetry
    environment variables or an auto-instrumentation deployment. Core SnowImpact does
    not require telemetry packages to run.
    """
    if not enabled:
        return False
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry import trace
    except ImportError:
        log.warning("OpenTelemetry requested but optional dependencies are not installed")
        return False

    provider = trace.get_tracer_provider()
    # Avoid replacing a provider already configured by the deployment environment.
    if provider.__class__.__name__ == "ProxyTracerProvider":
        trace.set_tracer_provider(TracerProvider(resource=Resource.create({"service.name": "snowimpact"})))
    FastAPIInstrumentor.instrument_app(app)
    return True
