"""Public-only collection of CVE and supporting evidence.

This collector is deliberately conservative: HTTPS-only, a small allowlist of
security-source hosts, response size bounds, no redirects, and network timeouts.
Unexpected source failures are reported, never silently interpreted as proof.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .models import SourceRecord, utc_now
from .security import host_has_public_addresses, url_allowed

LOGGER = logging.getLogger(__name__)
MAX_RESPONSE_BYTES = 250_000
MAX_SOURCE_CHARS = 14_000


class SourceError(RuntimeError):
    pass


def fetch_public(url: str, *, session: requests.Session | None = None) -> str:
    if not url_allowed(url):
        raise SourceError(f"Source URL is not in the trusted HTTPS host allowlist: {url}")
    host = urlparse(url).hostname
    if not host or not host_has_public_addresses(host):
        raise SourceError(f"Cannot verify public DNS addresses for {host}")
    client = session or requests.Session()
    try:
        # No redirects or arbitrary URL following; size bound applies while streaming.
        with client.get(url, timeout=(6, 15), allow_redirects=False, stream=True,
                        headers={"User-Agent": "Vuln-Skill/0.1 (defensive research)",
                                 "Accept": "application/json, text/html, text/plain"}) as response:
            if response.status_code != 200:
                raise SourceError(f"HTTP {response.status_code} fetching {url}")
            data = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                data.extend(chunk)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise SourceError(f"Source exceeds size limit: {url}")
            return data.decode(response.encoding or "utf-8", errors="replace")
    except requests.RequestException as exc:
        raise SourceError(f"Fetching {url} failed: {exc}") from exc


def extract_readable_text(raw: str) -> str:
    soup = BeautifulSoup(raw, "html.parser")
    for elem in soup(["script", "style", "noscript", "header", "footer", "nav"]):
        elem.decompose()
    main = soup.select_one("main") or soup.select_one("article") or soup.body or soup
    text = main.get_text(" ", strip=True)
    return re.sub(r"\s+", " ", text)[:MAX_SOURCE_CHARS]


def _cna_source(cve_id: str, payload: dict) -> tuple[SourceRecord, list[str]]:
    metadata = payload.get("cveMetadata", {})
    if metadata.get("state") != "PUBLISHED" or metadata.get("cveId", "").upper() != cve_id:
        raise SourceError(f"CVE is not a matching published record: {cve_id}")
    cna = payload.get("containers", {}).get("cna", {})
    desc = [x.get("value", "") for x in cna.get("descriptions", []) if x.get("lang") == "en"]
    affected = cna.get("affected", [])
    refs = cna.get("references", [])
    ref_urls = [r.get("url", "") for r in refs if r.get("url")]
    # Preserve literal advisory wording for evidence substring checks.
    text = (
        "CVE: " + cve_id + "\n"
        + "CNA: " + metadata.get("assignerShortName", "Unknown") + "\n"
        + "DESCRIPTION:\n" + "\n".join(desc) + "\n"
        + "AFFECTED RECORDS:\n" + json.dumps(affected, ensure_ascii=False) + "\n"
        + "REFERENCES:\n" + "\n".join(ref_urls)
    )[:MAX_SOURCE_CHARS]
    if not desc:
        raise SourceError("CVE CNA has no English vulnerability description")
    return SourceRecord(id="CVE-CNA", title=f"Official CNA record for {cve_id}",
                        url=f"https://cveawg.mitre.org/api/cve/{cve_id}",
                        authority="CVE/CNA", text=text, fetched_at=utc_now()), ref_urls


def collect_sources(cve_id: str, *, max_references: int = 3) -> list[SourceRecord]:
    """Fetch fresh public evidence; secondary sources may repeat CNA content."""
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id, re.IGNORECASE):
        raise SourceError("Expected a CVE identifier such as CVE-2026-82901")
    cve_id = cve_id.upper()
    cve_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        primary, reference_urls = _cna_source(cve_id, json.loads(fetch_public(cve_url)))
    except (ValueError, json.JSONDecodeError) as exc:
        raise SourceError(f"Invalid official CVE JSON for {cve_id}") from exc
    sources = [primary]

    # GHSA is optional: GitHub's advisory API can be rate limited or return no matches.
    try:
        payload = json.loads(fetch_public(f"https://api.github.com/advisories?cve_id={cve_id}"))
        if isinstance(payload, list):
            for item in payload[:2]:
                text = (
                    "CVE: " + cve_id + "\n"
                    + "SUMMARY: " + (item.get("summary") or "") + "\n"
                    + "DESCRIPTION:\n" + (item.get("description") or "") + "\n"
                    + "VULNERABILITIES:\n" + json.dumps(item.get("vulnerabilities", []), ensure_ascii=False)
                )[:MAX_SOURCE_CHARS]
                if len(text) > 80:
                    sources.append(SourceRecord(
                        id=f"GHSA-{len(sources)}", title=item.get("summary", "GitHub Security Advisory"),
                        url=item.get("html_url") or "https://github.com/advisories",
                        authority="GHSA", text=text, fetched_at=utc_now()))
    except (SourceError, ValueError, TypeError) as exc:
        LOGGER.warning("Optional GHSA source unavailable: %s", exc)

    picked = 0
    for url in reference_urls:
        if picked >= max_references:
            break
        if not url_allowed(url):
            continue
        # Do not count the same exact URL twice; no generic web crawling.
        if any(s.url == url for s in sources):
            continue
        try:
            raw = fetch_public(url)
            text = extract_readable_text(raw)
            if len(text) < 100:
                continue
            picked += 1
            sources.append(SourceRecord(id=f"REF-{picked}", title=f"Advisory reference {picked}",
                                        url=url, authority=urlparse(url).hostname or "reference",
                                        text=text, fetched_at=utc_now()))
        except SourceError as exc:
            LOGGER.warning("Optional reference unavailable: %s", exc)
    return sources
