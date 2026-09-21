"""End-to-end test in a real Gecko browser (Firefox or Zen).

Builds an e2e flavour of the extension (identical bundles + permission for a local Gmail mock),
installs it as a temporary add-on, opens fixture emails in the mock and checks that MailShark
dissects them, renders its UI, blocks a dangerous link and that the Lab works.

    lab/.venv/Scripts/python tests/e2e_firefox.py [--browser "C:/Program Files/Zen Browser/zen.exe"] [--shots DIR]
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request

from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

ROOT = pathlib.Path(__file__).resolve().parents[1]
PORT = 5179
ORIGIN = f"http://localhost:{PORT}"
EXT_ID = "mailshark@jyo-coded.github.io"
EXT_UUID = "5a1e5a1e-0000-4000-8000-00000000cafe"
CANDIDATE_BROWSERS = [
    r"C:\Program Files\Mozilla Firefox\firefox.exe",
    r"C:\Program Files\Zen Browser\zen.exe",
    "/usr/bin/firefox",
    "/Applications/Firefox.app/Contents/MacOS/firefox",
]


def fixture_ids() -> dict[str, str]:
    files = sorted(p.name for p in (ROOT / "fixtures" / "eml").glob("*.eml"))
    return {name[:-4]: f"18f2a1c0de{i + 1:06x}" for i, name in enumerate(files)}


def wait_http(url: str, timeout: float = 60) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=2)
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"server did not start: {url}")


def js(driver, script: str, *args):
    return driver.execute_script(script, *args)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--browser", default=next((b for b in CANDIDATE_BROWSERS if os.path.exists(b)), None))
    ap.add_argument("--shots", default=str(ROOT / "artifacts" / "e2e"))
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--geckodriver", default=os.environ.get("GECKODRIVER"), help="path to geckodriver (needed for Zen/forks)")
    args = ap.parse_args()
    if not args.browser:
        print("No Firefox-family browser found; pass --browser")
        return 2
    shots = pathlib.Path(args.shots)
    shots.mkdir(parents=True, exist_ok=True)

    out = ROOT / "dist" / "firefox-e2e"
    subprocess.run(
        ["node", "-e", f"import('./scripts/build-lib.mjs').then(m => m.buildExtension({{ target: 'firefox', out: {json.dumps(str(out))}, testOrigin: '{ORIGIN}' }}))"],
        cwd=ROOT,
        check=True,
    )
    server = subprocess.Popen(["node", "scripts/preview.mjs"], cwd=ROOT, env={**os.environ, "PORT": str(PORT)}, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    failures: list[str] = []
    driver = None
    try:
        wait_http(ORIGIN + "/")
        opts = Options()
        opts.binary_location = args.browser
        if not args.headed:
            opts.add_argument("-headless")
        opts.add_argument("--width=1400")
        opts.add_argument("--height=900")
        opts.set_preference("extensions.webextensions.uuids", json.dumps({EXT_ID: EXT_UUID}))
        opts.set_preference("ui.systemUsesDarkTheme", 0)
        service = Service(executable_path=args.geckodriver) if args.geckodriver else None
        driver = webdriver.Firefox(options=opts, service=service) if service else webdriver.Firefox(options=opts)
        driver.set_window_size(1400, 900)
        main_handle = driver.current_window_handle
        driver.install_addon(str(out), temporary=True)
        time.sleep(2)
        welcome_handle = next((h for h in driver.window_handles if h != main_handle), None)
        # The welcome tab opens on install and takes focus; MailShark pauses inbox scanning in
        # background tabs, so bring the Gmail tab back to the front.
        driver.switch_to.window(main_handle)
        ids = fixture_ids()

        def check(name: str, cond: bool) -> None:
            print(("PASS " if cond else "FAIL ") + name)
            if not cond:
                failures.append(name)

        # 1) Opened phishing email → banner, then the link guard.
        driver.get(f"{ORIGIN}/mail/u/0/?real=1&open={ids['paypal-lookalike-credential']}")
        deadline = time.time() + 20
        host = None
        while time.time() < deadline and host is None:
            host = js(driver, "return document.querySelector('[data-mailshark-host=\"banner\"]')")
            time.sleep(0.3)
        check("banner host injected above the message body", host is not None)
        time.sleep(2.5)
        driver.save_screenshot(str(shots / "01-banner.png"))

        handles_before = len(driver.window_handles)
        link = driver.find_element(By.CSS_SELECTOR, "div.a3s a")
        link.click()
        time.sleep(1.0)
        driver.save_screenshot(str(shots / "02-link-guard.png"))
        trace = js(driver, "return document.documentElement.getAttribute('data-mailshark-e2e-click')")
        check(f"dangerous link intercepted ({trace})", trace == "match:3" and len(driver.window_handles) == handles_before)

        # 2) Dissector drawer via the banner's Dissect button (closed shadow root → click by offset).
        ActionChains(driver).send_keys("\ue00c").perform()  # Escape closes the guard
        time.sleep(0.5)
        rect = js(driver, "const r=document.querySelector('[data-mailshark-host=\"banner\"]').getBoundingClientRect();return {x:r.x,y:r.y,w:r.width,h:r.height};")
        ActionChains(driver).move_to_element_with_offset(host, int(rect["w"] / 2) - 150, int(-rect["h"] / 2) + 26).click().perform()
        time.sleep(1.5)
        overlay = js(driver, "return !!document.querySelector('[data-mailshark-host=\"overlay\"]')")
        check("overlay host present (drawer/guard layer)", bool(overlay))
        driver.save_screenshot(str(shots / "03-dissector.png"))

        # 3) Inbox radar on the list view.
        driver.get(f"{ORIGIN}/mail/u/0/?real=1")
        deadline = time.time() + 45
        badges = 0
        while time.time() < deadline:
            badges = js(driver, "return document.querySelectorAll('[data-mailshark-host=\"badge\"]').length")
            if badges >= 10:
                break
            time.sleep(1)
        time.sleep(2)
        driver.save_screenshot(str(shots / "04-radar.png"))
        check(f"inbox radar badges rendered ({badges})", badges >= 10)

        # 4) Extension pages (privileged: WebDriver may screenshot and click, not script or navigate).
        check("welcome tab opened on install", welcome_handle is not None)
        if welcome_handle:
            driver.switch_to.window(welcome_handle)
            time.sleep(1.5)
            driver.save_screenshot(str(shots / "05-welcome.png"))
            try:
                before = set(driver.window_handles)
                driver.find_element(By.XPATH, "//button[contains(., 'Explore the Lab')]").click()
                time.sleep(2.5)
                lab = next(iter(set(driver.window_handles) - before), None)
                check("Lab opens from the welcome page", lab is not None)
                if lab:
                    driver.switch_to.window(lab)
                    time.sleep(2.0)
                    driver.save_screenshot(str(shots / "06-lab.png"))
                    driver.find_element(By.XPATH, "//button[contains(., 'Campaigns')]").click()
                    time.sleep(1.5)
                    driver.save_screenshot(str(shots / "07-campaigns.png"))
                    cards = driver.find_elements(By.CSS_SELECTOR, ".ms-camp-card")
                    check(f"campaign traced across rotated variants ({len(cards)} card)", len(cards) >= 1)
                    if cards:
                        cards[0].click()
                        time.sleep(2.0)
                        driver.save_screenshot(str(shots / "08-campaign-detail.png"))
                    driver.find_element(By.XPATH, "//button[contains(., 'Academy')]").click()
                    time.sleep(1.0)
                    driver.save_screenshot(str(shots / "09-academy.png"))
                    driver.find_element(By.XPATH, "//button[contains(., 'Settings')]").click()
                    time.sleep(1.0)
                    driver.save_screenshot(str(shots / "10-settings.png"))
            except Exception as exc:  # noqa: BLE001
                check(f"extension pages interactive ({type(exc).__name__}: {exc})", False)
    finally:
        if driver:
            driver.quit()
        server.terminate()
    print(f"\n{len(failures)} failure(s). Screenshots in {shots}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
