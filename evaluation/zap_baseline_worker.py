"""Fixed A06 driver. Executed only inside the pinned ZAP container, never on host."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from urllib.request import ProxyHandler, build_opener

API = "http://127.0.0.1:8080"
TARGET = "http://juice:3000"
OUT = Path("/out")
OPENER = build_opener(ProxyHandler({}))


def api(component, kind, operation, **params):
    url = f"{API}/JSON/{component}/{kind}/{operation}/?{urlencode(params)}"
    with OPENER.open(url, timeout=20) as response:
        result = json.load(response)
    if "code" in result:
        raise RuntimeError(f"ZAP {component}/{operation}: {result['code']}")
    return result


def write(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def wait_until(predicate, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(1)
    return False


def run():
    # Prevent accidentally running this module on the operator's computer.
    if os.getenv("CFT_A06_CONTAINER") != "1" or not Path("/.dockerenv").exists():
        raise RuntimeError("A06 ZAP worker is Docker-only")
    profile = json.loads(Path("/input/profile.json").read_text())
    budget = profile["budgets"]
    coverage = {"role": "anonymous", "target": TARGET, "stages": {}, "errors": [],
                "limitations": ["No authenticated roles or cross-user workflows",
                                 "No OAST: scanner has no external network access",
                                 "No business-logic oracle or exhaustive route coverage"],
                "seeds": [], "urls": [], "truncated": False}
    log = (OUT / "zap.log").open("w", encoding="utf-8")
    proc = subprocess.Popen([
        "zap.sh", "-daemon", "-silent", "-host", "127.0.0.1", "-port", "8080",
        "-dir", "/tmp/zap-home", "-config", "api.disablekey=true",
        "-config", "connection.timeoutInSecs=10", "-config", "spider.thread=2",
        "-config", "ascan.threadPerHost=2", "-config", "autoupdate.checkOnStart=false",
    ], stdout=log, stderr=subprocess.STDOUT)
    try:
        def ready():
            try:
                return bool(api("core", "view", "version"))
            except (OSError, ValueError):
                return False
        if not wait_until(ready, budget["startup_seconds"]):
            raise RuntimeError("ZAP startup timed out")
        write("versions.json", {"zap": api("core", "view", "version"),
              "addons": api("autoupdate", "view", "installedAddons"),
              "active_rules": api("ascan", "view", "scanners"),
              "passive_rules": api("pscan", "view", "scanners")})
        context = api("context", "action", "newContext", contextName="a06")["contextId"]
        api("context", "action", "includeInContext", contextName="a06",
            regex=re.escape(TARGET) + r"/.*")
        api("context", "action", "setContextInScope", contextName="a06", booleanInScope="true")
        api("pscan", "action", "setScanOnlyInScope", onlyInScope="true")
        api("pscan", "action", "setMaxBodySizeInBytes", maxSize=budget["passive_body_bytes"])
        coverage["passive_body_limit_bytes"] = budget["passive_body_bytes"]
        coverage["limitations"].append("Passive body analysis skips oversized responses")
        api("spider", "action", "setOptionMaxDepth", Integer=5)
        for path in profile["seeds"]:
            result = api("core", "action", "accessUrl", url=TARGET + path,
                         followRedirects="false")
            messages = result.get("accessUrl", [])
            coverage["seeds"].append({"path": path, "responses": [
                {"status": m.get("responseHeader", "").split("\r\n", 1)[0]}
                for m in messages]})
        scan = api("spider", "action", "scan", url=TARGET + "/", maxChildren=10,
                   recurse="true", contextName="a06", subtreeOnly="true")["scan"]
        done = wait_until(lambda: int(api("spider", "view", "status", scanId=scan)["status"])
                          == 100, budget["spider_seconds"])
        if not done:
            api("spider", "action", "stop", scanId=scan)
        coverage["stages"]["spider"] = {"complete": done, "budget_seconds": budget["spider_seconds"]}
        api("ajaxSpider", "action", "setOptionBrowserId", String="firefox-headless")
        api("ajaxSpider", "action", "setOptionNumberOfBrowsers", Integer=1)
        api("ajaxSpider", "action", "setOptionMaxCrawlDepth", Integer=5)
        api("ajaxSpider", "action", "scan", url=TARGET + "/", inScope="true",
            contextName="a06", subtreeOnly="true")
        # Start is asynchronous: the initial stopped status is not completion.
        started = False
        def ajax_complete():
            nonlocal started
            status = api("ajaxSpider", "view", "status")["status"]
            count = int(api("ajaxSpider", "view", "numberOfResults")["numberOfResults"])
            started = started or status != "stopped" or count > 0
            return started and status == "stopped"
        done = wait_until(ajax_complete, budget["ajax_seconds"])
        if not done:
            api("ajaxSpider", "action", "stop")
        # Stop is asynchronous; prevent browser traffic feeding the passive queue
        # after the crawl budget. A browser failure must not look like an empty scan.
        wait_until(lambda: api("ajaxSpider", "view", "status")["status"] == "stopped", 15)
        ajax_results = int(api("ajaxSpider", "view", "numberOfResults")["numberOfResults"])
        coverage["stages"]["ajax"] = {"complete": done, "budget_seconds": budget["ajax_seconds"],
                                       "results": ajax_results}
        if ajax_results == 0:
            raise RuntimeError("AJAX spider produced no results; browser availability unproven")
        # ZAP's default installed policy; no truth-derived rules, endpoints or payloads.
        api("ascan", "action", "setOptionMaxScanDurationInMins",
            Integer=max(1, (budget["active_seconds"] + 59) // 60))
        scan = api("ascan", "action", "scan", url=TARGET + "/", recurse="true",
                   inScopeOnly="true", contextId=context)["scan"]
        done = wait_until(lambda: int(api("ascan", "view", "status", scanId=scan)["status"])
                          == 100, budget["active_seconds"])
        if not done:
            api("ascan", "action", "stop", scanId=scan)
        coverage["stages"]["active"] = {"complete": done, "budget_seconds": budget["active_seconds"]}
        done = wait_until(lambda: int(api("pscan", "view", "recordsToScan")["recordsToScan"])
                          == 0, budget["passive_seconds"])
        coverage["stages"]["passive"] = {"complete": done}
        if not done:
            coverage["errors"].append("Passive scan queue did not drain")
        coverage["passive_remaining"] = int(api("pscan", "view", "recordsToScan")["recordsToScan"])
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        coverage["errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        try:
            alerts = api("core", "view", "alerts", baseurl=TARGET,
                         start=0, count=budget["max_alerts"] + 1)
            if len(alerts.get("alerts", [])) > budget["max_alerts"]:
                coverage["errors"].append("Alert limit reached; raw observations incomplete")
            write("raw.json", alerts)
            urls = api("core", "view", "urls", baseurl=TARGET)["urls"]
            urls = sorted({u for u in urls if urlsplit(u).netloc == "juice:3000"})
            coverage["url_count"] = len(urls)
            coverage["truncated"] = len(urls) > budget["max_urls"]
            coverage["urls"] = urls[:budget["max_urls"]]
            # Full coverage is retained; display list is bounded independently.
            write("urls.json", urls)
        except (OSError, ValueError, RuntimeError, KeyError) as exc:
            coverage["errors"].append(f"Artifact collection: {type(exc).__name__}: {exc}")
        write("coverage.json", coverage)
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()
    return 2 if coverage["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(run())
