FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN useradd --create-home --uid 10001 snowimpact
COPY pyproject.toml README.md LICENSE ./
COPY snowimpact ./snowimpact
COPY policies ./policies
RUN pip install --upgrade pip && pip install .
USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
CMD ["uvicorn", "snowimpact.api.app:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
