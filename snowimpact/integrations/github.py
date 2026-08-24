from __future__ import annotations

import base64
import time
from typing import Any
from urllib.parse import quote

import httpx
import jwt


class GitHubAppClient:
    """Minimal GitHub App client for PR analysis and check-run publication."""

    def __init__(self, app_id: str, private_key: str, api_url: str = "https://api.github.com"):
        self.app_id = app_id
        self.private_key = private_key
        self.api_url = api_url.rstrip("/")
        self._default_headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SnowImpact/1.0",
        }

    def app_jwt(self) -> str:
        now = int(time.time())
        payload = {"iat": now - 30, "exp": now + 540, "iss": self.app_id}
        return jwt.encode(payload, self.private_key, algorithm="RS256")

    def installation_token(self, installation_id: int) -> str:
        headers = {**self._default_headers, "Authorization": f"Bearer {self.app_jwt()}"}
        with httpx.Client(timeout=20) as client:
            response = client.post(
                f"{self.api_url}/app/installations/{installation_id}/access_tokens",
                headers=headers,
            )
            response.raise_for_status()
            return str(response.json()["token"])

    def _headers(self, token: str) -> dict[str, str]:
        return {**self._default_headers, "Authorization": f"Bearer {token}"}

    def pull_request_files(
        self,
        token: str,
        owner: str,
        repo: str,
        pull_number: int,
        *,
        max_files: int = 500,
    ) -> list[dict[str, Any]]:
        """Return changed PR files with pagination and a hard safety bound."""
        files: list[dict[str, Any]] = []
        page = 1
        with httpx.Client(timeout=30) as client:
            while len(files) < max_files:
                response = client.get(
                    f"{self.api_url}/repos/{owner}/{repo}/pulls/{pull_number}/files",
                    headers=self._headers(token),
                    params={"per_page": 100, "page": page},
                )
                response.raise_for_status()
                batch = response.json()
                if not isinstance(batch, list):
                    raise RuntimeError("Unexpected GitHub pull-files response")
                files.extend(batch)
                if len(batch) < 100:
                    break
                page += 1
        return files[:max_files]

    def file_text(
        self,
        token: str,
        owner: str,
        repo: str,
        path: str,
        ref: str,
        *,
        max_bytes: int = 2_000_000,
    ) -> str:
        """Fetch one repository file at an immutable ref. Reject unexpectedly large files."""
        encoded_path = quote(path, safe="/")
        with httpx.Client(timeout=30) as client:
            response = client.get(
                f"{self.api_url}/repos/{owner}/{repo}/contents/{encoded_path}",
                headers=self._headers(token),
                params={"ref": ref},
            )
            response.raise_for_status()
            body = response.json()
        if body.get("type") != "file":
            raise ValueError(f"GitHub path is not a file: {path}")
        size = int(body.get("size") or 0)
        if size > max_bytes:
            raise ValueError(f"Refusing GitHub file larger than {max_bytes} bytes: {path}")
        content = body.get("content") or ""
        if body.get("encoding") != "base64":
            raise ValueError(f"Unsupported GitHub content encoding for {path}")
        decoded = base64.b64decode(content, validate=False)
        if len(decoded) > max_bytes:
            raise ValueError(f"Refusing decoded GitHub file larger than {max_bytes} bytes: {path}")
        return decoded.decode("utf-8")

    def changed_sql(
        self,
        token: str,
        owner: str,
        repo: str,
        pull_number: int,
        head_sha: str,
    ) -> tuple[str, list[str]]:
        """Fetch added/modified/renamed SQL files and combine them for deterministic analysis."""
        chunks: list[str] = []
        paths: list[str] = []
        for file in self.pull_request_files(token, owner, repo, pull_number):
            path = str(file.get("filename") or "")
            status = str(file.get("status") or "")
            if not path.lower().endswith(".sql") or status == "removed":
                continue
            text = self.file_text(token, owner, repo, path, head_sha)
            paths.append(path)
            chunks.append(f"-- SnowImpact source: {path}\n{text.rstrip()}\n")
        return "\n;\n".join(chunks), paths

    def create_check_run(
        self,
        token: str,
        owner: str,
        repo: str,
        head_sha: str,
        result: dict[str, Any],
        *,
        details_url: str | None = None,
    ) -> dict[str, Any]:
        decision = str(result.get("decision", "unknown"))
        conclusion = {
            "block": "failure",
            "require_approval": "action_required",
            "warn": "neutral",
            "unknown": "neutral",
            "allow": "success",
        }.get(decision, "neutral")
        findings = result.get("findings", []) or []
        top = sorted(findings, key=lambda item: int(item.get("risk_score", 0)), reverse=True)[:20]
        lines = [
            f"* **{str(item.get('severity', 'info')).upper()}** `{item.get('rule', 'UNKNOWN')}`. {item.get('title', '')}"
            for item in top
        ]
        summary = (
            f"Decision: **{decision.upper()}**. Risk: **{result.get('risk', {}).get('overall', 0)}/100**. "
            f"Findings: **{len(findings)}**. Metadata coverage: **{result.get('coverage_percent', 0)}%**."
        )
        output = {
            "title": f"SnowImpact risk {result.get('risk', {}).get('overall', 0)}/100",
            "summary": summary,
            "text": "\n".join(lines) if lines else "No policy findings detected.",
        }
        payload: dict[str, Any] = {
            "name": "SnowImpact / Overall",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": output,
        }
        if details_url:
            payload["details_url"] = details_url
        with httpx.Client(timeout=20) as client:
            response = client.post(
                f"{self.api_url}/repos/{owner}/{repo}/check-runs",
                headers=self._headers(token),
                json=payload,
            )
            response.raise_for_status()
            return response.json()

    def create_noop_check_run(
        self,
        token: str,
        owner: str,
        repo: str,
        head_sha: str,
        message: str = "No changed SQL files require analysis.",
    ) -> dict[str, Any]:
        payload = {
            "name": "SnowImpact / Overall",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": "success",
            "output": {"title": "SnowImpact. No analyzable SQL changes", "summary": message},
        }
        with httpx.Client(timeout=20) as client:
            response = client.post(
                f"{self.api_url}/repos/{owner}/{repo}/check-runs",
                headers=self._headers(token),
                json=payload,
            )
            response.raise_for_status()
            return response.json()
