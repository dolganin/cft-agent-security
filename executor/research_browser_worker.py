"""Fixed Playwright worker in a networkless container; host broker supplies bytes.

Only operator code evaluates the fixed DOM projection below. Model input is data,
never a script, CDP command, browser option, URL origin or storage-state object.
"""
import asyncio
import base64
import hashlib
import json
import sys
from urllib.parse import urlsplit

DOM = """() => ({
  text: (document.body?.innerText || '').slice(0, 6000),
  elements: Array.from(document.querySelectorAll('input,button,a,textarea,select'))
    .slice(0,30).map((e,i) => ({index:i, tag:e.tagName.toLowerCase(),
      id:e.id.slice(0,120), name:(e.getAttribute('name') || '').slice(0,120),
      type:(e.getAttribute('type') || '').slice(0,40),
      text:(e.innerText || e.getAttribute('aria-label') || '').slice(0,120)}))
})"""


def emit(value):
    print(json.dumps(value, ensure_ascii=True), flush=True)


async def main():
    from playwright.async_api import TimeoutError as BrowserTimeoutError
    from playwright.async_api import async_playwright

    reader = asyncio.StreamReader(limit=3145728)
    pipe, _ = await asyncio.get_running_loop().connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
    payload = json.loads(await reader.readline())
    request = payload["request"]
    origin = "http://research-target.invalid"
    dialogs, snapshots, errors = [], [], []
    count = 0
    transport_lock = asyncio.Lock()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--disable-background-networking",
            "--disable-component-update", "--disable-quic", "--disable-webrtc",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
        context = await browser.new_context(service_workers="block", accept_downloads=False,
                                      viewport={"width": 1024, "height": 768})
        async def close_socket(ws):
            await ws.close()

        await context.route_web_socket("**/*", close_socket)

        async def route_request(route):
            nonlocal count
            req = route.request
            url = urlsplit(req.url)
            if (url.scheme != "http" or url.netloc != "research-target.invalid"
                    or count >= payload["max_requests"]):
                await route.abort()
                return
            count += 1
            async with transport_lock:
                emit({"transport": {"method": req.method, "path": url.path + ("?" + url.query if url.query else ""),
                    "body": req.post_data or "", "headers": {k:v for k,v in req.headers.items()
                        if k.lower() in {"accept", "content-type"}}}})
                response = json.loads(await reader.readline())
            if response.get("denied"):
                await route.abort()
            else:
                await route.fulfill(status=response["status"], headers=response["headers"],
                              body=base64.b64decode(response["body_base64"]))

        await context.route("**/*", route_request)
        page = await context.new_page()
        page.set_default_timeout(1800)
        page.set_default_navigation_timeout(24000)

        async def dialog_event(dialog):
            if len(dialogs) < 8:
                dialogs.append({"type": dialog.type, "message": dialog.message[:1024]})
            await dialog.dismiss()

        page.on("dialog", dialog_event)
        page.on("pageerror", lambda error: errors.append(str(error)[:300]) if len(errors) < 8 else None)
        async def close_popup(popup):
            if popup != page:
                await popup.close()

        context.on("page", close_popup)
        try:
            emit({"progress":"navigate"})
            await page.goto(origin + request["path"] + ("#" + request["fragment"] if request["fragment"] else ""),
                      wait_until="commit")
            navigation_complete = True
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=12000)
            except BrowserTimeoutError:
                navigation_complete = False
            emit({"progress":"initial_snapshot"})
            snapshots.append(await page.evaluate(DOM))
            for step in request["steps"]:
                operation = step["operation"]
                emit({"progress":operation})
                if operation == "snapshot":
                    snapshots.append(await page.evaluate(DOM))
                    continue
                locator = page.locator(step["selector"])
                if await locator.count() != 1:
                    raise ValueError("Selector must identify exactly one observed element")
                if operation == "fill":
                    await locator.fill(step["value"])
                elif operation == "click":
                    await locator.click()
                elif operation == "press":
                    await locator.press(step["value"])
                else:
                    raise ValueError("Unsupported browser operation")
            settled = True
            try:
                await page.wait_for_load_state("networkidle", timeout=3000)
            except BrowserTimeoutError:
                settled = False
            emit({"progress":"final_snapshot"})
            snapshots.append(await page.evaluate(DOM))
            screenshot, screenshot_error = None, None
            if request["screenshot"]:
                try:
                    screenshot = await page.screenshot(type="png", timeout=4000, animations="disabled")
                except BrowserTimeoutError:
                    screenshot_error = "timeout"
            result = {"kind": "browser_observation", "snapshots": snapshots[-3:], "dialogs": dialogs[:8],
                "page_errors": errors, "requests": count, "storage_persisted": False,
                "network_settled":settled,
                "navigation_complete":navigation_complete,
                "screenshot_error":screenshot_error,
                "network_mode": "none", "verdict": "inconclusive",
                "screenshot_base64": base64.b64encode(screenshot).decode() if screenshot else None,
                "screenshot_sha256": hashlib.sha256(screenshot).hexdigest() if screenshot else None}
            emit({"result": result})
        finally:
            await context.close()
            await browser.close()
            pipe.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:  # noqa: BLE001 - fixed isolated worker exit boundary
        emit({"error": type(exc).__name__})
        sys.exit(2)
