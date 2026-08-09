"""
Universal Website Screenshot Endpoint using Playwright Headless Browser
SSRF Protected, Offline SQLite Caching, Anti-Detection Chrome User-Agent.
Route: GET /api/screenshot?url=xxx
"""

import re
import base64
import urllib.parse
from fastapi import APIRouter, Query, HTTPException
from app.database import get_cached_screenshot, save_cached_screenshot

router = APIRouter(tags=["Screenshot"])

# SSRF Protection: Block internal / private IPs & loopbacks
BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]",
}

PRIVATE_IP_REGEX = re.compile(
    r"^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
)


def validate_and_clean_url(url_str: str) -> str:
    """Validate input URL and prevent SSRF attacks."""
    if not url_str:
        raise HTTPException(status_code=400, detail="URL parameter is required")

    url = url_str.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.netloc or parsed.path).split(":")[0].lower()

    if not hostname or hostname in BLOCKED_HOSTS or PRIVATE_IP_REGEX.match(hostname):
        raise HTTPException(status_code=400, detail="Access to private or local IP addresses is prohibited")

    return url


@router.get("/api/screenshot")
def take_website_screenshot(url: str = Query(..., description="Target website URL to render screenshot")):
    """
    Capture live website screenshot using Playwright Headless Chromium.
    Checks 24h SQLite cache first before launching browser.
    """
    clean_url = validate_and_clean_url(url)

    # Step 1: Check 24-hour SQLite Cache First
    cached_b64 = get_cached_screenshot(clean_url)
    if cached_b64:
        return {
            "url": clean_url,
            "screenshot": cached_b64,
            "cached": True,
            "success": True
        }

    print(f"[Screenshot Route] Capturing live Playwright screenshot for {clean_url}...")

    # Step 2: Launch Playwright Sync Chromium
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                ]
            )

            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 800},
                device_scale_factor=1,
            )

            # Anti-detection script: Hide webdriver property
            context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

            page = context.new_page()

            try:
                page.goto(clean_url, wait_until="domcontentloaded", timeout=20000)
                page.wait_for_timeout(2500)
            except Exception as nav_err:
                print(f"[Screenshot Nav Warning for {clean_url}]: {nav_err}")

            # Capture PNG screenshot bytes
            png_bytes = page.screenshot(full_page=False, type="png")
            browser.close()

            b64_str = f"data:image/png;base64,{base64.b64encode(png_bytes).decode('utf-8')}"

            # Save to SQLite Cache
            save_cached_screenshot(clean_url, b64_str)

            return {
                "url": clean_url,
                "screenshot": b64_str,
                "cached": False,
                "success": True
            }

    except Exception as e:
        print(f"[Playwright Screenshot Exception for {clean_url}]: {e}")
        return {
            "url": clean_url,
            "screenshot": None,
            "cached": False,
            "success": False,
            "error": str(e)
        }
