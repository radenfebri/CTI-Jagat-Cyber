from __future__ import annotations

import hmac
import os
import re
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator


app = FastAPI(title="CTI Jagat Cyber Scanner", version="0.1.0")


class FingerprintRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    base_domain: str = Field(min_length=1, max_length=253)

    @field_validator("hostname", "base_domain")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        normalized = value.strip().lower().rstrip(".")
        labels = normalized.split(".")
        if (
            not re.fullmatch(r"[a-z0-9.-]{1,253}", normalized)
            or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels)
        ):
            raise ValueError("hostname must be a DNS hostname")
        return normalized


def authorize(authorization: str | None) -> None:
    expected = os.getenv("CTI_WORKER_TOKEN", "")
    supplied = authorization.removeprefix("Bearer ").strip() if authorization else ""
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=401, detail="Worker authentication failed")


def ensure_scope(hostname: str, base_domain: str) -> None:
    if hostname != base_domain and not hostname.endswith(f".{base_domain}"):
        raise HTTPException(status_code=422, detail="Hostname is outside the requested domain scope")


def add_fact(facts: list[dict[str, str]], name: str, version: str | None, source: str) -> None:
    key = (name.lower(), (version or "").lower())
    if any((fact["name"].lower(), fact.get("version", "").lower()) == key for fact in facts):
        return
    fact: dict[str, str] = {"name": name, "source": source}
    if version:
        fact["version"] = version
    facts.append(fact)


def fingerprint(response: httpx.Response) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    headers = {key.lower(): value for key, value in response.headers.items()}
    body = response.content[:131_072].decode(response.encoding or "utf-8", errors="ignore")
    powered_by = headers.get("x-powered-by", "")
    server = headers.get("server", "")

    php = re.search(r"php[/ ]([0-9][0-9.]+)", powered_by, re.IGNORECASE)
    if php:
        add_fact(facts, "PHP", php.group(1), "header")
    elif "php" in powered_by.lower():
        add_fact(facts, "PHP", None, "header")

    express = re.search(r"express[/ ]([0-9][0-9.]+)", powered_by, re.IGNORECASE)
    if express:
        add_fact(facts, "Express", express.group(1), "header")
    elif "express" in powered_by.lower():
        add_fact(facts, "Express", None, "header")

    for pattern, name in ((r"apache[/ ]([0-9][0-9.]+)", "Apache"), (r"nginx[/ ]([0-9][0-9.]+)", "Nginx"), (r"caddy[/ ]([0-9][0-9.]+)", "Caddy"), (r"microsoft-iis[/ ]([0-9][0-9.]+)", "IIS")):
        match = re.search(pattern, server, re.IGNORECASE)
        if match:
            add_fact(facts, name, match.group(1), "header")
    if "cloudflare" in f"{server} {headers.get('cf-ray', '')}".lower():
        add_fact(facts, "Cloudflare", None, "header")

    generator = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", body, re.IGNORECASE)
    if generator and "wordpress" in generator.group(1).lower():
        version = re.search(r"wordpress\s*([0-9][0-9.]+)", generator.group(1), re.IGNORECASE)
        add_fact(facts, "WordPress", version.group(1) if version else None, "body")
    elif "wp-content/" in body.lower() or "/wp-includes/" in body.lower():
        add_fact(facts, "WordPress", None, "body")

    for pattern, name in ((r"bootstrap(?:@|/|-)([0-9][0-9.]+)", "Bootstrap"), (r"jquery(?:\.min)?\.js[^\"']*", "jQuery"), (r"(?:react|react-dom)(?:@|/|-)([0-9][0-9.]+)", "React"), (r"vue(?:@|/|-)([0-9][0-9.]+)", "Vue"), (r"angular(?:@|/|-)([0-9][0-9.]+)", "Angular")):
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            add_fact(facts, name, match.group(1) if match.lastindex else None, "body")

    if "laravel_session=" in headers.get("set-cookie", "").lower():
        add_fact(facts, "Laravel", None, "header")
    return facts


@app.get("/health")
async def health(authorization: str | None = Header(default=None)) -> dict[str, str]:
    authorize(authorization)
    return {"status": "ok", "service": "cti-scanner-python"}


@app.post("/v1/fingerprint")
async def fingerprint_asset(
    payload: FingerprintRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    authorize(authorization)
    ensure_scope(payload.hostname, payload.base_domain)

    async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(30.0, connect=5.0)) as client:
        response: httpx.Response | None = None
        scheme = "https"
        for candidate in ("https", "http"):
            try:
                candidate_response = await client.get(
                    f"{candidate}://{payload.hostname}/",
                    headers={"User-Agent": "CTI-Jagat-Cyber-Scanner/0.1"},
                )
            except httpx.HTTPError:
                continue
            response = candidate_response
            scheme = candidate
            break

    if response is None:
        return {
            "hostname": payload.hostname,
            "scheme": None,
            "status_code": None,
            "server_header": None,
            "technologies": [],
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    server_header = response.headers.get("server")
    return {
        "hostname": payload.hostname,
        "scheme": scheme,
        "status_code": response.status_code,
        "server_header": server_header,
        "technologies": fingerprint(response),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
