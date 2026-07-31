#!/usr/bin/env python3
"""Isolated Firefox acceptance check for an AdaptivePool proxy.

Requires Firefox, geckodriver and selenium. The temporary profile is removed
on exit. URLs are reported as origins only; query strings and signed targets
are never printed or persisted.
"""

import argparse
import json
import sys
import time
from urllib.parse import urlsplit

from selenium import webdriver
from selenium.webdriver.firefox.options import Options


DEFAULT_URLS = [
    "https://www.google.com/generate_204",
    "https://github.com/",
    "https://www.youtube.com/watch?v=ePcGDDtW1Sk",
]


def origin(raw_url: str) -> str:
    parsed = urlsplit(raw_url)
    return f"{parsed.scheme}://{parsed.netloc}/"


def configure_proxy(options: Options, proxy_type: str, host: str, port: int) -> None:
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
    options.set_preference("media.autoplay.default", 0)


def run(args: argparse.Namespace) -> int:
    options = Options()
    if args.headless:
        options.add_argument("-headless")
    configure_proxy(options, args.proxy_type, args.proxy_host, args.proxy_port)
    results = []
    driver = webdriver.Firefox(options=options)
    driver.set_page_load_timeout(args.timeout)
    try:
        for raw_url in args.url:
            started = time.monotonic()
            result = {"origin": origin(raw_url), "ok": False}
            try:
                driver.get(raw_url)
                result["title_present"] = bool(driver.title.strip()) or "generate_204" in raw_url
                if "youtube.com" in urlsplit(raw_url).hostname:
                    state = driver.execute_async_script(
                        """
                        const done = arguments[arguments.length - 1];
                        const deadline = Date.now() + 15000;
                        const check = () => {
                          const video = document.querySelector('video');
                          if (!video) { if (Date.now() < deadline) return setTimeout(check, 250); return done({found:false}); }
                          video.muted = true;
                          Promise.resolve(video.play()).catch(() => {}).finally(() =>
                            setTimeout(() => done({found:true, ready:video.readyState, time:video.currentTime, paused:video.paused}), 3000));
                        };
                        check();
                        """
                    )
                    result["video"] = state
                    result["ok"] = bool(state.get("found") and state.get("ready", 0) >= 2 and state.get("time", 0) > 0)
                else:
                    result["ok"] = bool(result["title_present"])
            except Exception as error:  # Never serialize a URL-bearing exception.
                result["error_type"] = type(error).__name__
            result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
            results.append(result)
    finally:
        driver.quit()
    print(json.dumps({"proxy_type": args.proxy_type, "targets": results}, separators=(",", ":")))
    return 0 if all(item["ok"] for item in results) else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy-type", choices=("http", "socks5"), default="http")
    parser.add_argument("--proxy-host", required=True)
    parser.add_argument("--proxy-port", type=int, required=True)
    parser.add_argument("--url", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()
    if not args.url:
        args.url = DEFAULT_URLS
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
