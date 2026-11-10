#!/usr/bin/env python3
"""Filesystem queue bridge for sandboxes that cannot connect to Unix sockets."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import uuid


ALLOWED_TASK_PREFIXES = ("_db:", "_mesh:")


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def prepare_queue(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.stat()
    if metadata.st_uid != os.getuid():
        raise SystemExit(f"queue is owned by another uid: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        os.chmod(path, 0o700)


def valid_request(path: Path) -> bool:
    metadata = path.lstat()
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
        and metadata.st_size <= 65536
    )


def serve(queue: Path, socket_path: str, agent: str) -> int:
    prepare_queue(queue)
    lock = open(queue / ".bridge.lock", "a+", encoding="utf-8")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit(f"bridge is already running for {queue}")

    stopping = False

    def stop(*_: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(f"[mise-agent-bridge] queue={queue}", file=sys.stderr, flush=True)

    while not stopping:
        requests = sorted(queue.glob("request-*.json"), key=lambda item: item.stat().st_mtime)
        if not requests:
            time.sleep(0.05)
            continue

        for request_path in requests:
            if stopping:
                break
            request_id = request_path.stem.removeprefix("request-")
            processing = queue / f"processing-{request_id}.json"
            response = queue / f"response-{request_id}.json"
            try:
                if not valid_request(request_path):
                    raise ValueError("invalid request file")
                os.replace(request_path, processing)
                request = json.loads(processing.read_text(encoding="utf-8"))
                operation = request.get("op")
                if operation == "run":
                    task = request.get("task")
                    if not isinstance(task, str) or not task.startswith(ALLOWED_TASK_PREFIXES):
                        raise ValueError("bridge only accepts _db:* and _mesh:* tasks")
                    command = [agent, "--socket", socket_path, "run", task]
                elif operation in {"ping", "list"}:
                    command = [agent, "--socket", socket_path, operation]
                elif operation == "cancel":
                    job = request.get("job")
                    if not isinstance(job, str):
                        raise ValueError("cancel requires a job id")
                    command = [agent, "--socket", socket_path, "cancel", job]
                else:
                    raise ValueError(f"unsupported operation: {operation!r}")

                completed = subprocess.run(
                    command,
                    cwd=Path(agent).resolve().parent.parent,
                    capture_output=True,
                    text=True,
                    timeout=1900,
                    check=False,
                )
                result = {
                    "exit": completed.returncode,
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                }
            except Exception as error:
                result = {"exit": 1, "stdout": "", "stderr": f"bridge: {error}\n"}
            finally:
                processing.unlink(missing_ok=True)
            atomic_json(response, result)

    return 0


def request(queue: Path, payload: dict, timeout: float) -> int:
    prepare_queue(queue)
    request_id = uuid.uuid4().hex
    request_path = queue / f"request-{request_id}.json"
    response_path = queue / f"response-{request_id}.json"
    atomic_json(request_path, payload)
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if response_path.exists():
                result = json.loads(response_path.read_text(encoding="utf-8"))
                sys.stdout.write(result.get("stdout", ""))
                sys.stderr.write(result.get("stderr", ""))
                return int(result.get("exit", 1))
            time.sleep(0.05)
        print(f"bridge response timed out after {timeout:g}s", file=sys.stderr)
        return 124
    finally:
        request_path.unlink(missing_ok=True)
        response_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--queue", required=True, type=Path)
    parser.add_argument("--agent", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve")
    run = commands.add_parser("run")
    run.add_argument("task")
    commands.add_parser("ping")
    commands.add_parser("list")
    cancel = commands.add_parser("cancel")
    cancel.add_argument("job")
    args = parser.parse_args()

    if args.command == "serve":
        return serve(args.queue, args.socket, args.agent)
    if args.command == "run":
        payload = {"op": "run", "task": args.task}
    elif args.command == "cancel":
        payload = {"op": "cancel", "job": args.job}
    else:
        payload = {"op": args.command}
    return request(args.queue, payload, 1900)


if __name__ == "__main__":
    raise SystemExit(main())
