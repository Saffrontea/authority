"""One TCP echo attempt with stream framing, a shared deadline and diagnostics."""
import socket
import time

PAYLOAD = b'TCP_ADMISSION_OK'


class EchoFailure(AssertionError):
    def __init__(self, stage, received, cause):
        super().__init__(f'{stage}: {type(cause).__name__}; received={received}')
        self.stage = stage
        self.received = received
        self.cause = cause


def remaining(deadline, clock):
    duration = deadline - clock()
    if duration <= 0:
        raise TimeoutError('TCP probe deadline exceeded')
    return duration


def echo(stream, *, deadline=None, clock=time.monotonic):
    if deadline is None:
        deadline = clock() + (stream.gettimeout() or 1)
    received = bytearray()
    stage = 'send'
    try:
        stream.settimeout(remaining(deadline, clock))
        stream.sendall(PAYLOAD)
        stage = 'receive'
        while len(received) < len(PAYLOAD):
            stream.settimeout(remaining(deadline, clock))
            chunk = stream.recv(len(PAYLOAD) - len(received))
            if not chunk:
                raise EOFError('incomplete TCP echo')
            received.extend(chunk)
        if received != PAYLOAD:
            raise ValueError('incorrect TCP echo')
    except (OSError, EOFError, ValueError) as cause:
        raise EchoFailure(stage, len(received), cause) from cause


def probe(host, port, timeout=1, *, connector=socket.create_connection, clock=time.monotonic):
    """Return a bounded observation, never retry or reinterpret an error as success."""
    start = clock()
    result = {'admitted': False, 'stage': 'connect', 'received_bytes': 0}
    try:
        with connector((host, port), timeout=remaining(start + timeout, clock)) as stream:
            echo(stream, deadline=start + timeout, clock=clock)
        result.update(admitted=True, stage='complete', received_bytes=len(PAYLOAD))
    except EchoFailure as failure:
        result.update(stage=failure.stage, received_bytes=failure.received,
                      error=type(failure.cause).__name__, errno=getattr(failure.cause, 'errno', None))
    except OSError as cause:
        result.update(error=type(cause).__name__, errno=cause.errno)
    result['elapsed_ms'] = round((clock() - start) * 1000, 3)
    return result
