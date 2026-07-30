#!/usr/bin/env python3
"""Ephemeral Firefox qualification for AI chat landing pages.

The detector uses a fresh browser profile and never persists cookies, page
content, screenshots, query strings, tokens, or browser exceptions. Output is
limited to service, origin, structured outcome, signal and elapsed time.
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

@dataclass(frozen=True)
class ChatProfile:
    origin: str
    allowed_hosts: tuple[str, ...]
    region_markers: tuple[str, ...]


PROFILES = {
    "chatgpt": ChatProfile(
        origin="https://chatgpt.com/",
        allowed_hosts=("chatgpt.com", "auth.openai.com"),
        region_markers=(
            "unsupported_country",
            "unsupported country",
            "not available in your country",
            "not available in your region",
            "services are not available in your country",
        ),
    ),
    "claude": ChatProfile(
        origin="https://claude.ai/",
        allowed_hosts=("claude.ai", "claude.com"),
        region_markers=(
            "claude is not available in your country",
            "claude is not available in your region",
            "not currently available in your region",
            "access to anthropic models is not available in your region",
        ),
    ),
    "gemini": ChatProfile(
        origin="https://gemini.google.com/",
        allowed_hosts=("gemini.google.com", "accounts.google.com"),
        region_markers=(
            "gemini isn't available in your country",
            "gemini is not available in your country",
            "gemini isn't available in your region",
            "gemini is not available in your region",
        ),
    ),
}

CHALLENGE_MARKERS = (
    "verify you are human",
    "checking your browser",
    "performing security verification",
    "enable javascript and cookies to continue",
    "just a moment",
)


def origin(raw_url: str) -> str:
    parsed = urlsplit(raw_url)
    return f"{parsed.scheme}://{parsed.netloc}/"


def classify_chat_page(service: str, final_url: str, title: str, body_text: str, ready_state: str) -> dict:
    profile = PROFILES[service]
    host = (urlsplit(final_url).hostname or "").lower()
    title_lower = (title or "").strip().lower()
    body_lower = (body_text or "").strip().lower()
    combined = f"{title_lower}\n{body_lower}"
    result = {"service": service, "origin": origin(final_url) if host else profile.origin}

    if host not in profile.allowed_hosts:
        result.update(outcome="invalid", signal="unexpected_origin")
        return result
    if any(marker in combined for marker in profile.region_markers):
        result.update(outcome="blocked_region", signal="region_marker")
        return result
    if any(marker in combined for marker in CHALLENGE_MARKERS):
        result.update(outcome="transient_challenge", signal="browser_challenge")
        return result
    if ready_state != "complete":
        result.update(outcome="transient", signal="document_incomplete")
        return result
    if not title_lower and len(body_lower) < 16:
        result.update(outcome="transient", signal="empty_document")
        return result
    result.update(outcome="eligible", signal="landing_ready")
    return result


def configure_proxy(options, proxy_type: str, host: str, port: int) -> None:
    options.set_preference("network.proxy.type", 1)
    if proxy_type == "socks5":
        options.set_preference("network.proxy.socks", host)
        options.set_preference("network.proxy.socks_port", port)
        options.set_preference("network.proxy.socks_version", 5)
        options.set_preference("network.proxy.socks_remote_dns", True)
    else:
        options.set_preference("network.proxy.http", host)
        options.set_preference("network.proxy.http_port", port)
        options.set_preference("network.proxy.ssl", host)
        options.set_preference("network.proxy.ssl_port", port)
    options.set_preference("network.proxy.no_proxies_on", "localhost, 127.0.0.1")
    options.set_preference("network.http.http3.enable", False)
    options.set_preference("browser.cache.disk.enable", False)
    options.set_preference("browser.privatebrowsing.autostart", True)


def inspect_service(driver, service: str, timeout: int) -> dict:
    profile = PROFILES[service]
    started = time.monotonic()
    result = {"service": service, "origin": profile.origin, "outcome": "transient", "signal": "navigation_error"}
    try:
        driver.set_page_load_timeout(timeout)
        driver.get(profile.origin)
        page = driver.execute_script(
            """
            return {
              url: location.href,
              title: document.title || '',
              body: document.body ? document.body.innerText.slice(0, 131072) : '',
              ready: document.readyState
            };
            """
        )
        result = classify_chat_page(service, page["url"], page["title"], page["body"], page["ready"])
    except Exception as error:  # Never serialize URL-bearing exception text.
        result["signal"] = type(error).__name__
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def run(args: argparse.Namespace) -> int:
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options

    options = Options()
    if args.headless:
        options.add_argument("-headless")
    configure_proxy(options, args.proxy_type, args.proxy_host, args.proxy_port)
    driver = webdriver.Firefox(options=options)
    try:
        results = [inspect_service(driver, service, args.timeout) for service in args.service]
    finally:
        driver.quit()
    print(json.dumps({"schema": 1, "targets": results}, separators=(",", ":")))
    return 0 if all(result["outcome"] == "eligible" for result in results) else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy-type", choices=("http", "socks5"), default="http")
    parser.add_argument("--proxy-host", required=True)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--service", action="append", choices=tuple(PROFILES), default=[])
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()
    if not args.service:
        args.service = list(PROFILES)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
