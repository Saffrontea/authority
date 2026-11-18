"""Pinned TLC discovery shared by model checks and runtime trace replay."""
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TLC_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
TLC_URL = "https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar"


def checker():
    java = os.environ.get("TLA_JAVA") or shutil.which("java")
    if not java or not shutil.which(java):
        raise SystemExit("Java 11+ is required; set TLA_JAVA to its executable (no checks skipped)")
    jar = Path(os.environ.get("TLA_JAR", ROOT / ".cache/formal/tla2tools-1.7.4.jar"))
    if not jar.exists():
        jar.parent.mkdir(parents=True, exist_ok=True)
        # Do not leave a partial cached download after a failed transfer.
        with tempfile.NamedTemporaryFile(dir=jar.parent) as download:
            urllib.request.urlretrieve(TLC_URL, download.name)
            data = Path(download.name).read_bytes()
            if hashlib.sha256(data).hexdigest() != TLC_SHA256:
                raise SystemExit("downloaded TLC checksum mismatch")
            jar.write_bytes(data)
    if hashlib.sha256(jar.read_bytes()).hexdigest() != TLC_SHA256:
        raise SystemExit("TLC checksum mismatch")
    return java, jar.resolve()
