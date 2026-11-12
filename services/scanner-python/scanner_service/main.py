from __future__ import annotations

import asyncio
import hmac
import html
import ipaddress
import os
import re
import socket
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator


app = FastAPI(title="CTI Jagat Cyber Scanner", version="0.2.0")

SCANNER_USER_AGENT = "CTI-Jagat-Cyber-Scanner/0.2"
MAX_HTML_BYTES = 524_288
MAX_SCRIPT_BYTES = 524_288
MAX_REDIRECTS = 5


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


class PageSignals(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.links: list[str] = []
        self.anchors: list[str] = []
        self.meta: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "") for name, value in attrs}
        if tag.lower() == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"])
        elif tag.lower() == "link" and attributes.get("href"):
            self.links.append(attributes["href"])
        elif tag.lower() == "a" and attributes.get("href"):
            self.anchors.append(attributes["href"])
        elif tag.lower() == "meta":
            key = (attributes.get("name") or attributes.get("property") or "").lower()
            if key and attributes.get("content"):
                self.meta[key] = attributes["content"]


def authorize(authorization: str | None) -> None:
    expected = os.getenv("CTI_WORKER_TOKEN", "")
    supplied = authorization.removeprefix("Bearer ").strip() if authorization else ""
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=401, detail="Worker authentication failed")


def ensure_scope(hostname: str, base_domain: str) -> None:
    if hostname != base_domain and not hostname.endswith(f".{base_domain}"):
        raise HTTPException(status_code=422, detail="Hostname is outside the requested domain scope")


def is_in_scope(hostname: str | None, base_domain: str) -> bool:
    return bool(hostname) and (hostname == base_domain or hostname.endswith(f".{base_domain}"))


async def resolves_to_public_address(hostname: str) -> bool:
    try:
        addresses = await asyncio.get_running_loop().run_in_executor(
            None,
            lambda: socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM),
        )
    except socket.gaierror:
        return False

    resolved = {entry[4][0].split("%", 1)[0] for entry in addresses}
    return bool(resolved) and all(ipaddress.ip_address(address).is_global for address in resolved)


def add_fact(
    facts: list[dict[str, str]],
    name: str,
    version: str | None,
    source: str,
    category: str,
) -> None:
    normalized_name = name.strip()
    normalized_version = version.strip() if version else None
    for fact in facts:
        if fact["name"].lower() != normalized_name.lower():
            continue
        if fact.get("version", "").lower() == (normalized_version or "").lower():
            return
        if not fact.get("version") and normalized_version:
            fact.update({"version": normalized_version, "source": source, "category": category})
            return
        if fact.get("version") and not normalized_version:
            return

    fact = {"name": normalized_name, "source": source, "category": category}
    if normalized_version:
        fact["version"] = normalized_version
    facts.append(fact)


def parse_page(body: str) -> PageSignals:
    parser = PageSignals()
    try:
        parser.feed(body)
    except (AssertionError, ValueError):
        pass
    return parser


def version_from(text: str, product_pattern: str) -> str | None:
    match = re.search(
        rf"{product_pattern}(?:\.min)?(?:@|[/_.-]|\s+v?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        text,
        re.IGNORECASE,
    )
    return match.group(1) if match else None


def detect_resource(resource_url: str, facts: list[dict[str, str]]) -> None:
    lowered = resource_url.lower()
    hostname = (urlparse(resource_url).hostname or "").lower()

    providers = (
        ("cdn.jsdelivr.net", "jsDelivr"),
        ("unpkg.com", "Unpkg"),
        ("cdnjs.cloudflare.com", "cdnjs"),
    )
    for provider, name in providers:
        if hostname == provider or hostname.endswith(f".{provider}"):
            add_fact(facts, name, None, "resource_url", "CDN")

    if hostname in {"fonts.googleapis.com", "fonts.gstatic.com"}:
        add_fact(facts, "Google Font API", None, "resource_url", "Font scripts")
    if "static.cloudflareinsights.com/beacon" in lowered:
        add_fact(facts, "Cloudflare Browser Insights", None, "resource_url", "RUM")
    if "googletagmanager.com/gtag" in lowered or "google-analytics.com" in lowered:
        add_fact(facts, "Google Analytics", None, "resource_url", "Analytics")
    if "googletagmanager.com/gtm" in lowered:
        add_fact(facts, "Google Tag Manager", None, "resource_url", "Tag managers")
    if "clarity.ms/tag" in lowered:
        add_fact(facts, "Microsoft Clarity", None, "resource_url", "Analytics")
    if "hotjar.com" in hostname or "hotjar.io" in hostname:
        add_fact(facts, "Hotjar", None, "resource_url", "Analytics")
    if "client.crisp.chat" in lowered:
        add_fact(facts, "Crisp", None, "resource_url", "Live chat")
    if "embed.tawk.to" in lowered:
        add_fact(facts, "Tawk.to", None, "resource_url", "Live chat")
    if "intercom" in hostname or "intercom" in lowered:
        add_fact(facts, "Intercom", None, "resource_url", "Live chat")

    packages = (
        (r"jquery", "jQuery", "JavaScript libraries"),
        (r"bootstrap", "Bootstrap", "UI frameworks"),
        (r"iconify(?:-icon)?", "Iconify", "JavaScript libraries"),
        (r"lodash", "Lodash", "JavaScript libraries"),
        (r"axios", "Axios", "JavaScript libraries"),
        (r"react(?:-dom)?", "React", "JavaScript frameworks"),
        (r"vue(?:\.global)?", "Vue.js", "JavaScript frameworks"),
        (r"angular", "Angular", "JavaScript frameworks"),
        (r"next(?:\.js)?", "Next.js", "Web frameworks"),
        (r"nuxt", "Nuxt.js", "Web frameworks"),
        (r"alpine(?:js)?", "Alpine.js", "JavaScript frameworks"),
        (r"tailwindcss", "Tailwind CSS", "UI frameworks"),
    )
    for pattern, name, category in packages:
        if re.search(pattern, lowered, re.IGNORECASE):
            add_fact(facts, name, version_from(lowered, pattern), "resource_url", category)


def fingerprint(response: httpx.Response) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    headers = {key.lower(): value for key, value in response.headers.items()}
    body = response.content[:MAX_HTML_BYTES].decode(response.encoding or "utf-8", errors="ignore")
    lowered_body = body.lower()
    powered_by = headers.get("x-powered-by", "")
    server = headers.get("server", "")
    page = parse_page(body)

    php = re.search(r"php[/ ]([0-9][0-9.]+)", powered_by, re.IGNORECASE)
    if php:
        add_fact(facts, "PHP", php.group(1), "header", "Programming languages")
    elif "php" in powered_by.lower():
        add_fact(facts, "PHP", None, "header", "Programming languages")

    express = re.search(r"express[/ ]([0-9][0-9.]+)", powered_by, re.IGNORECASE)
    if express:
        add_fact(facts, "Express", express.group(1), "header", "Web frameworks")
    elif "express" in powered_by.lower():
        add_fact(facts, "Express", None, "header", "Web frameworks")
    if "asp.net" in powered_by.lower() or "aspnet" in headers.get("set-cookie", "").lower():
        add_fact(facts, "ASP.NET", version_from(powered_by, r"asp\.net"), "header", "Web frameworks")

    servers = (
        (r"apache[/ ]([0-9][0-9.]+)", "Apache"),
        (r"nginx[/ ]([0-9][0-9.]+)", "Nginx"),
        (r"caddy[/ ]([0-9][0-9.]+)", "Caddy"),
        (r"microsoft-iis[/ ]([0-9][0-9.]+)", "IIS"),
    )
    for pattern, name in servers:
        match = re.search(pattern, server, re.IGNORECASE)
        if match:
            add_fact(facts, name, match.group(1), "header", "Web servers")
    if server and not any(fact["category"] == "Web servers" for fact in facts):
        for token, name in (("apache", "Apache"), ("nginx", "Nginx"), ("caddy", "Caddy"), ("microsoft-iis", "IIS")):
            if token in server.lower():
                add_fact(facts, name, None, "header", "Web servers")

    if "cloudflare" in f"{server} {headers.get('cf-ray', '')}".lower():
        add_fact(facts, "Cloudflare", None, "header", "CDN")
    if "h3" in headers.get("alt-svc", "").lower():
        add_fact(facts, "HTTP/3", None, "header", "Protocols")
    if response.http_version.upper() == "HTTP/2":
        add_fact(facts, "HTTP/2", None, "transport", "Protocols")

    generator = page.meta.get("generator", "")
    for product in ("WordPress", "Drupal", "Joomla"):
        if product.lower() in generator.lower():
            add_fact(facts, product, version_from(generator, re.escape(product)), "meta", "CMS")
    if "wp-content/" in lowered_body or "/wp-includes/" in lowered_body:
        add_fact(facts, "WordPress", None, "body", "CMS")
    if any(key.startswith("og:") for key in page.meta):
        add_fact(facts, "Open Graph", None, "meta", "Metadata")

    cookie = headers.get("set-cookie", "").lower()
    if "laravel_session=" in cookie:
        add_fact(facts, "Laravel", None, "cookie", "Web frameworks")
    if "next.js" in powered_by.lower():
        add_fact(facts, "Next.js", None, "header", "Web frameworks")

    resources = [*page.scripts, *page.links]
    for resource in resources[:80]:
        detect_resource(urljoin(str(response.url), html.unescape(resource.strip())), facts)

    if "--tw-" in lowered_body or "tailwindcss" in lowered_body:
        add_fact(facts, "Tailwind CSS", version_from(lowered_body, r"tailwindcss"), "body", "UI frameworks")
    if "--bs-" in lowered_body:
        add_fact(facts, "Bootstrap", None, "body", "UI frameworks")
    if "__next_data__" in lowered_body or "/_next/static/" in lowered_body:
        add_fact(facts, "Next.js", None, "body", "Web frameworks")
    if "__nuxt__" in lowered_body or "/_nuxt/" in lowered_body:
        add_fact(facts, "Nuxt.js", None, "body", "Web frameworks")
    if "data-reactroot" in lowered_body or "react-dom" in lowered_body:
        add_fact(facts, "React", None, "body", "JavaScript frameworks")
    if re.search(r"\bng-version=[\"']", lowered_body) or re.search(r"\bng-app(?:=|\s)", lowered_body):
        add_fact(facts, "Angular", None, "body", "JavaScript frameworks")
    if re.search(r"\bx-data(?:=|\s)", lowered_body):
        add_fact(facts, "Alpine.js", None, "body", "JavaScript frameworks")

    for anchor in page.anchors[:100]:
        parsed = urlparse(urljoin(str(response.url), anchor))
        if parsed.hostname in {"wa.me", "api.whatsapp.com", "web.whatsapp.com"}:
            add_fact(facts, "WhatsApp Business Chat", None, "link", "Live chat")

    return facts


def script_urls(response: httpx.Response) -> list[str]:
    body = response.content[:MAX_HTML_BYTES].decode(response.encoding or "utf-8", errors="ignore")
    page = parse_page(body)
    urls: list[str] = []
    for source in page.scripts:
        candidate = urljoin(str(response.url), html.unescape(source.strip()))
        if urlparse(candidate).scheme not in {"http", "https"} or candidate in urls:
            continue
        urls.append(candidate)
        if len(urls) >= 20:
            break
    return urls


def javascript_facts(script_url: str, body: str) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    detect_resource(script_url, facts)
    haystack = f"{script_url}\n{body[:MAX_SCRIPT_BYTES]}"
    patterns = (
        (r"jquery", "jQuery", "JavaScript libraries"),
        (r"bootstrap", "Bootstrap", "UI frameworks"),
        (r"iconify(?:-icon)?", "Iconify", "JavaScript libraries"),
        (r"lodash", "Lodash", "JavaScript libraries"),
        (r"axios", "Axios", "JavaScript libraries"),
        (r"react(?:-dom)?", "React", "JavaScript frameworks"),
        (r"vue", "Vue.js", "JavaScript frameworks"),
        (r"angular", "Angular", "JavaScript frameworks"),
        (r"next(?:\.js)?", "Next.js", "Web frameworks"),
    )
    for pattern, name, category in patterns:
        version = version_from(haystack, pattern)
        if version:
            add_fact(facts, name, version, "javascript", category)
    return facts


async def fingerprint_javascript(
    client: httpx.AsyncClient,
    response: httpx.Response,
    base_domain: str,
) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    for url in script_urls(response):
        parsed = urlparse(url)
        facts.extend(javascript_facts(url, ""))
        if not is_in_scope(parsed.hostname, base_domain) or not await resolves_to_public_address(parsed.hostname or ""):
            continue
        try:
            script = await client.get(url, headers={"User-Agent": SCANNER_USER_AGENT})
        except httpx.HTTPError:
            continue
        if script.status_code >= 400:
            continue
        script_body = script.content[:MAX_SCRIPT_BYTES].decode(script.encoding or "utf-8", errors="ignore")
        facts.extend(javascript_facts(url, script_body))

    unique: list[dict[str, str]] = []
    for fact in facts:
        add_fact(unique, fact["name"], fact.get("version"), fact["source"], fact["category"])
    return unique


async def fetch_scoped(
    client: httpx.AsyncClient,
    url: str,
    base_domain: str,
) -> httpx.Response | None:
    current = url
    response: httpx.Response | None = None
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current)
        if parsed.scheme not in {"http", "https"} or not is_in_scope(parsed.hostname, base_domain):
            return None
        if not await resolves_to_public_address(parsed.hostname or ""):
            return None
        try:
            response = await client.get(current, headers={"User-Agent": SCANNER_USER_AGENT})
        except httpx.HTTPError:
            return None
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("location")
        if not location:
            return response
        next_url = urljoin(current, location)
        if not is_in_scope(urlparse(next_url).hostname, base_domain):
            return response
        current = next_url
    return response


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

    technologies: list[dict[str, str]] = []
    response: httpx.Response | None = None
    async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(30.0, connect=5.0)) as client:
        for candidate in ("https", "http"):
            response = await fetch_scoped(client, f"{candidate}://{payload.hostname}/", payload.base_domain)
            if response is not None:
                break
        if response is not None:
            technologies = fingerprint(response)
            javascript = await fingerprint_javascript(client, response, payload.base_domain)
            for fact in javascript:
                add_fact(technologies, fact["name"], fact.get("version"), fact["source"], fact["category"])

    if response is None:
        return {
            "hostname": payload.hostname,
            "scheme": None,
            "status_code": None,
            "server_header": None,
            "technologies": [],
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "hostname": payload.hostname,
        "scheme": response.url.scheme,
        "status_code": response.status_code,
        "server_header": response.headers.get("server"),
        "technologies": technologies,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
