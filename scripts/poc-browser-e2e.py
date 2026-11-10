#!/usr/bin/env python3
"""Drive the complete PoC with ChromeDriver's virtual WebAuthn authenticator."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import urllib.parse


ROOT = Path(__file__).resolve().parent.parent
DRIVER_ORIGIN = "http://127.0.0.1:9515"
ELEMENT_KEY = "element-6066-11e4-a52e-4f735466cecf"
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class WebDriverError(RuntimeError):
    pass


def request(method: str, path: str, body: object | None = None) -> object:
    payload = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        f"{DRIVER_ORIGIN}{path}",
        data=payload,
        method=method,
        headers={"content-type": "application/json"},
    )
    try:
        with HTTP.open(req, timeout=15) as response:
            envelope = json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise WebDriverError(f"{method} {path}: HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise WebDriverError(f"{method} {path}: {error}") from error
    value = envelope.get("value") if isinstance(envelope, dict) else None
    if isinstance(value, dict) and value.get("error"):
        raise WebDriverError(f"{method} {path}: {value}")
    return envelope.get("value") if isinstance(envelope, dict) else envelope


def json_request(url: str, body: object, headers: dict[str, str] | None = None) -> object:
    request_headers = {"content-type": "application/json", **(headers or {})}
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST", headers=request_headers
    )
    try:
        with HTTP.open(req, timeout=15) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")
        raise RuntimeError(f"POST {url}: HTTP {error.code}: {detail}") from error


def wait_until(predicate, description: str, timeout: float = 30.0):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except (WebDriverError, urllib.error.URLError) as error:
            last = error
        time.sleep(0.2)
    raise WebDriverError(f"timed out waiting for {description}; last={last}")


def find(session: str, selector: str) -> str:
    value = request(
        "POST",
        f"/session/{session}/element",
        {"using": "css selector", "value": selector},
    )
    return value[ELEMENT_KEY]


def set_value(session: str, selector: str, value: str) -> None:
    element = find(session, selector)
    request("POST", f"/session/{session}/element/{element}/clear", {})
    request(
        "POST",
        f"/session/{session}/element/{element}/value",
        {"text": value, "value": list(value)},
    )


def click(session: str, selector: str) -> None:
    element = find(session, selector)
    request("POST", f"/session/{session}/element/{element}/click", {})


def text(session: str, selector: str) -> str:
    element = find(session, selector)
    return str(request("GET", f"/session/{session}/element/{element}/text"))


def text_starting_with(session: str, selector: str, prefix: str) -> str | None:
    value = text(session, selector)
    return value if value.startswith(prefix) else None


def save_screenshot(session: str) -> Path:
    screenshot = request("GET", f"/session/{session}/screenshot")
    path = ROOT / "target" / "poc-e2e-failure.png"
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(base64.b64decode(screenshot))
    return path


def run() -> None:
    token = (ROOT / ".secrets" / "authority-bootstrap-token").read_text().strip()
    username = f"poc-e2e-{time.time_ns()}"
    session = ""
    wireguard_public_key = os.environ.get("AUTHORITY_POC_WG_PUBLIC_KEY")
    network_agent_origin = os.environ.get("AUTHORITY_POC_NETWORK_AGENT_ORIGIN")
    control_origin = os.environ.get("AUTHORITY_POC_CONTROL_ORIGIN", "http://localhost:3000")
    issuer_origin = os.environ.get("AUTHORITY_POC_ISSUER_ORIGIN", "http://localhost:3001")
    node_origin = os.environ.get("AUTHORITY_POC_NODE_ORIGIN", "http://localhost:3002")

    with tempfile.TemporaryDirectory(prefix="authority-chromedriver-") as temporary:
        log_path = Path(temporary) / "chromedriver.log"
        with log_path.open("wb") as log:
            driver = subprocess.Popen(
                [
                    "chromedriver",
                    "--port=9515",
                    "--allowed-ips=127.0.0.1",
                    "--log-level=WARNING",
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        try:
            wait_until(
                lambda: request("GET", "/status"),
                "ChromeDriver readiness",
                timeout=10,
            )
            capabilities = request(
                "POST",
                "/session",
                {
                    "capabilities": {
                        "alwaysMatch": {
                            "browserName": "chrome",
                            "webauthn:virtualAuthenticators": True,
                            "goog:chromeOptions": {
                                "binary": "/usr/bin/chromium",
                                "args": [
                                    "--headless=new",
                                    "--disable-gpu",
                                    "--disable-dev-shm-usage",
                                    "--no-first-run",
                                ],
                            },
                        }
                    }
                },
            )
            session = capabilities["sessionId"]
            request(
                "POST",
                f"/session/{session}/webauthn/authenticator",
                {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "isUserConsenting": True,
                    "isUserVerified": True,
                },
            )
            page_parameters = {
                "issuer_origin": issuer_origin,
                "node_agent_origin": node_origin,
            }
            if wireguard_public_key:
                page_parameters["wireguard_public_key"] = wireguard_public_key
            page_url = f"{control_origin}/?{urllib.parse.urlencode(page_parameters)}#bootstrap={token}"
            request(
                "POST",
                f"/session/{session}/url",
                {"url": page_url},
            )
            set_value(session, "#new-username", username)
            set_value(session, "#display-name", "Automated PoC")
            click(session, "#register")
            registered = wait_until(
                lambda: text_starting_with(
                    session, "#result", "Passkey registered."
                ),
                "Passkey registration",
            )
            if wireguard_public_key:
                target_line = next(line for line in registered.splitlines() if line.startswith("target="))
                target_id = target_line.removeprefix("target=")
                target_file = ROOT / ".secrets" / "poc-mesh-target-node-id"
                target_file.write_text(f"{target_id}\n")
                target_file.chmod(0o600)
                subprocess.run(["mise", "run", "mesh:agent:install"], cwd=ROOT, check=True)
            click(session, "#login")
            issued = wait_until(
                lambda: text_starting_with(
                    session,
                    "#result",
                    "Authenticated, authorized, and issued.",
                ),
                "Passkey authentication and SSH certificate issuance",
            )

            certificate = ROOT / ".secrets" / "poc-ssh" / "id_ed25519-cert.pub"
            inspection = subprocess.run(
                ["ssh-keygen", "-L", "-f", str(certificate)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            if "Principals:" not in inspection or "deploy" not in inspection:
                raise RuntimeError("issued certificate does not contain the deploy principal")
            print(registered)
            print(issued)
            if wireguard_public_key:
                browser_state = request(
                    "POST",
                    f"/session/{session}/execute/sync",
                    {
                        "script": "return {token: sessionStorage.getItem('authority-session'), access: JSON.parse(sessionStorage.getItem('authority-demo-access'))};",
                        "args": [],
                    },
                )
                grant = json_request(
                    f"{control_origin}/v1/network-access-grants",
                    {
                        "device_id": browser_state["access"]["device_id"],
                        "target_node_id": browser_state["access"]["target_node_id"],
                        "wireguard_public_key": wireguard_public_key,
                        "mesh_address": "10.77.0.1",
                    },
                    {"authorization": f"Bearer {browser_state['token']}"},
                )
                applied = json_request(
                    f"{network_agent_origin}/v1/network-grants", grant
                )
                print(
                    f"WireGuard peer applied.\npeer={applied['peer_public_key']}\n"
                    f"allowed={applied['allowed_ip']}\nexpires={applied['expires_at']}"
                )
                ttl = int(os.environ.get("AUTHORITY_NETWORK_GRANT_TTL_SECONDS", "5"))
                time.sleep(ttl + 2)
                expired = subprocess.run(
                    ["mise", "run", "mesh:verify"], cwd=ROOT, capture_output=True, text=True
                )
                if expired.returncode == 0:
                    raise RuntimeError("WireGuard peer remained active after grant expiry")
                print("WireGuard grant expiry: peer removed and tunnel denied")
                subprocess.run(["mise", "run", "mesh:configure"], cwd=ROOT, check=True)
            print("OpenSSH certificate validation: OK")
        except Exception:
            if session:
                try:
                    print(f"screenshot: {save_screenshot(session)}", file=sys.stderr)
                except Exception:
                    pass
            if log_path.exists():
                print(log_path.read_text(errors="replace"), file=sys.stderr)
            raise
        finally:
            if session:
                try:
                    request("DELETE", f"/session/{session}")
                except Exception:
                    pass
            driver.terminate()
            try:
                driver.wait(timeout=5)
            except subprocess.TimeoutExpired:
                driver.kill()


if __name__ == "__main__":
    run()
