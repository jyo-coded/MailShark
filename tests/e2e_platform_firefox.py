"""End-to-end test of the forensic platform web client in a real Gecko browser (Firefox or Zen).

Starts the built platform (dist/platform) on a throw-away data directory, then drives the UI the way
an investigator would: first-run setup, case creation, evidence upload through the file input,
processing, the message workspace (analysis tree, raw view, component highlighting), the graph,
report generation in three formats, and the phone layout. Fails on any page error Gecko reports.

    npm run platform:build
    lab/.venv/Scripts/python tests/e2e_platform_firefox.py [--browser PATH] [--shots DIR] [--headed]
"""

from __future__ import annotations

import argparse
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

ROOT = pathlib.Path(__file__).resolve().parents[1]
PORT = 7391
ORIGIN = f"http://127.0.0.1:{PORT}"
CANDIDATE_BROWSERS = [
    r"C:\Program Files\Mozilla Firefox\firefox.exe",
    r"C:\Program Files\Zen Browser\zen.exe",
    "/usr/bin/firefox",
    "/Applications/Firefox.app/Contents/MacOS/firefox",
]


def wait_http(url: str, timeout: float = 60) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=2)
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"server did not start: {url}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--browser", default=next((b for b in CANDIDATE_BROWSERS if os.path.exists(b)), None))
    ap.add_argument("--shots", default=str(ROOT / "artifacts" / "e2e-platform"))
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--geckodriver", default=os.environ.get("GECKODRIVER"))
    args = ap.parse_args()
    if not args.browser:
        print("No Firefox-family browser found; pass --browser")
        return 2
    if not (ROOT / "dist" / "platform" / "server.mjs").exists():
        print("Build the platform first: npm run platform:build")
        return 2
    shots = pathlib.Path(args.shots)
    shots.mkdir(parents=True, exist_ok=True)
    data = pathlib.Path(tempfile.mkdtemp(prefix="ms-e2e-platform-"))
    env = {**os.environ, "MAILSHARK_DATA_DIR": str(data), "MAILSHARK_PORT": str(PORT), "MAILSHARK_INTEL_AUTOSYNC": "false", "MAILSHARK_WORKERS": "2"}
    server = subprocess.Popen(["node", "--disable-warning=ExperimentalWarning", "dist/platform/server.mjs", "serve"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    log_path = shots / "browser.log"
    failures: list[str] = []
    driver = None
    password = secrets.token_urlsafe(14)  # generated per run, never printed

    def check(name: str, cond: bool) -> None:
        print(("PASS " if cond else "FAIL ") + name)
        if not cond:
            failures.append(name)

    def wait(fn, timeout: float = 30, step: float = 0.3):
        end = time.time() + timeout
        last = None
        while time.time() < end:
            try:
                last = fn()
                if last:
                    return last
            except Exception:  # noqa: BLE001
                pass
            time.sleep(step)
        return last

    try:
        wait_http(ORIGIN + "/api/health")
        token = wait(lambda: (data / "SETUP_TOKEN").read_text().strip(), 20)
        opts = Options()
        opts.binary_location = args.browser
        if not args.headed:
            opts.add_argument("-headless")
        opts.add_argument("--width=1440")
        opts.add_argument("--height=900")
        opts.set_preference("devtools.console.stdout.content", True)
        opts.set_preference("browser.dom.window.dump.enabled", True)
        service = Service(executable_path=args.geckodriver, log_output=str(log_path)) if args.geckodriver else Service(log_output=str(log_path))
        driver = webdriver.Firefox(options=opts, service=service)
        driver.set_window_size(1440, 900)
        q = lambda css: driver.find_element(By.CSS_SELECTOR, css)  # noqa: E731
        qa = lambda css: driver.find_elements(By.CSS_SELECTOR, css)  # noqa: E731
        js = driver.execute_script

        # 1) First-run setup creates the administrator and signs in.
        driver.get(ORIGIN + "/")
        wait(lambda: q("#t"))
        q("#t").send_keys(token)
        q("#u").send_keys("e2e-admin")
        q("#d").send_keys("E2E Admin")
        q("#p").send_keys(password)
        q("#c").send_keys(password)
        q("button[type=submit]").click()
        check("setup creates the administrator and opens the case list", bool(wait(lambda: "No cases yet" in q("#main").text)))
        driver.save_screenshot(str(shots / "01-cases-empty.png"))

        # 2) New case through the dialog.
        driver.find_element(By.XPATH, "//button[contains(., 'New case')]").click()
        wait(lambda: q("#cn")).send_keys("E2E: fixture intake")
        q("#cr").send_keys("E2E-0001")
        driver.find_element(By.XPATH, "//button[normalize-space()='Create case']").click()
        check("case created, evidence page opened", bool(wait(lambda: "/evidence" in driver.current_url and q(".dropzone"))))

        # 3) Upload the fixtures through the file input (as a user choosing files).
        emls = sorted((ROOT / "fixtures" / "eml").glob("*.eml"))
        inp = q(".dropzone input[type=file]")
        js("arguments[0].hidden = false", inp)
        inp.send_keys("\n".join(str(p) for p in emls))
        check(f"{len(emls)} files staged", bool(wait(lambda: f"{len(emls)} files" in q(".panel").text)))
        driver.find_element(By.XPATH, f"//button[contains(., 'Upload {len(emls)} files')]").click()
        check("batch accepted", bool(wait(lambda: f"{len(emls)} accepted" in q("#main").text, 60)))
        done = wait(lambda: "Idle" in q("#main").text and "up to date" in q("#main").text, 120, 1)
        check("processing and correlation finished (progress panel idle)", bool(done))
        driver.save_screenshot(str(shots / "02-evidence.png"))

        # 4) Overview shows the real counts.
        case_url = driver.current_url.split("/evidence")[0]
        driver.get(case_url)
        check("overview shows classification counts", bool(wait(lambda: "MALICIOUS" in q(".kpi-strip").text.upper() and q(".kpi-strip .k-value").text.strip() == str(len(emls)))))
        driver.save_screenshot(str(shots / "03-overview.png"))

        # 5) Message workspace: list → analysis tree → raw view → component highlighting.
        driver.get(case_url + "/messages?class=malicious")
        rows = wait(lambda: qa("table.t tbody tr.clickable"))
        check(f"malicious messages listed ({len(rows or [])})", bool(rows))
        rows[0].click()
        layers = wait(lambda: qa(".layer") if len(qa(".layer")) == 3 else None, 20)
        check("analysis shows assessment, external intelligence and observed evidence", bool(layers))
        check("raw message rendered", bool(wait(lambda: len(qa(".raw .ln")) > 10, 20)))
        chip = wait(lambda: qa(".ref-chip"))
        if chip:
            chip[0].click()
            check("clicking an affected component highlights raw lines", bool(wait(lambda: qa(".raw .ln[data-hl]"), 5)))
        else:
            check("an expanded finding lists affected components", False)
        driver.save_screenshot(str(shots / "04-workspace.png"))
        # Keyboard navigation moves the selection.
        before = driver.current_url
        js("document.activeElement && document.activeElement.blur()")
        driver.find_element(By.TAG_NAME, "body").send_keys("j")
        check("j moves to the next message", bool(wait(lambda: driver.current_url != before, 5)))

        # 6) Graph: canvas with real entities.
        driver.get(case_url + "/graph")
        stats = wait(lambda: next((e.text for e in qa(".hud-panel.stats") if "entities" in e.text), None), 30)
        check(f"graph built ({stats})", bool(stats) and not stats.startswith("0 entities"))
        time.sleep(3)
        driver.save_screenshot(str(shots / "05-graph.png"))

        # 7) Reports in three formats from one build.
        driver.get(case_url + "/reports")
        wait(lambda: driver.find_element(By.XPATH, "//button[contains(., 'Generate report')]"))
        for label in ("Markdown", "Word (DOCX)"):
            driver.find_element(By.XPATH, f"//label[contains(., '{label}')]/input").click()
        driver.find_element(By.XPATH, "//button[contains(., 'Generate report')]").click()
        reg = wait(lambda: qa("table.t tbody tr") if len(qa("table.t tbody tr")) >= 3 else None, 60)
        check("three report renderings registered", bool(reg))
        if reg:
            data_hashes = {r.find_elements(By.CSS_SELECTOR, "td")[4].text for r in reg[:3]}
            check("renderings share one data hash", len(data_hashes) == 1)
        driver.save_screenshot(str(shots / "06-reports.png"))

        # 8) Light theme and phone layout.
        driver.find_element(By.CSS_SELECTOR, "button[aria-label='Switch colour theme']").click()
        check("theme switches", bool(wait(lambda: js("return document.documentElement.getAttribute('data-theme')") == "light", 5)))
        driver.set_window_size(390, 844)
        driver.get(case_url + "/messages")
        wait(lambda: qa("table.t tbody tr"))
        overflow = js("return document.documentElement.scrollWidth - document.documentElement.clientWidth")
        check(f"no horizontal page scroll at phone width ({overflow}px)", overflow <= 0)
        driver.save_screenshot(str(shots / "07-phone.png"))
    except Exception as exc:  # noqa: BLE001
        check(f"flow completed without exception ({type(exc).__name__}: {exc})", False)
    finally:
        if driver:
            driver.quit()
        server.terminate()
    errors = []
    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if f"127.0.0.1:{PORT}" in line and any(k in line for k in ("Error", "error:", "Uncaught", "TypeError", "ReferenceError", "Content-Security-Policy")):
                errors.append(line.strip()[:300])
    check(f"no page errors or CSP violations in the browser log ({len(errors)})", not errors)
    for e in errors[:20]:
        print("   ", e)
    print(f"\n{len(failures)} failure(s). Screenshots in {shots}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
