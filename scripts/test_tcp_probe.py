"""Check observation fidelity independently of the LXC admission model."""
import errno
import random
import unittest

from tcp_probe import PAYLOAD, EchoFailure, echo, probe


class Clock:
    now = 0

    def __call__(self):
        return self.now


class Stream:
    def __init__(self, chunks, clock=None, delay=0):
        self.chunks = list(chunks)
        self.clock = clock or Clock()
        self.delay = delay
        self.timeout = 1
        self.timeouts = []
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout
        self.timeouts.append(timeout)

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, size):
        if self.delay > self.timeout:
            self.clock.now += self.timeout
            raise TimeoutError('delayed fragment')
        self.clock.now += self.delay
        if not self.chunks:
            return b''
        chunk = self.chunks.pop(0)
        if isinstance(chunk, Exception):
            raise chunk
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]


class TcpProbe(unittest.TestCase):
    def test_generated_stream_fragmentation_preserves_echo_success(self):
        for seed in range(256):
            rng = random.Random(seed)
            cuts = [0] + [i for i in range(1, len(PAYLOAD)) if rng.choice([False, True])] + [len(PAYLOAD)]
            stream = Stream([PAYLOAD[a:b] for a, b in zip(cuts, cuts[1:])])
            result = probe('fixture', 8080, connector=lambda *a, **k: stream, clock=stream.clock)
            self.assertTrue(result['admitted'], (seed, result))
            self.assertEqual(result['received_bytes'], len(PAYLOAD))
            self.assertEqual(stream.sent, [PAYLOAD])

    def test_wrong_and_truncated_echoes_are_not_admission(self):
        for data, error in [(b'x' * len(PAYLOAD), 'ValueError'), (PAYLOAD[:4], 'EOFError')]:
            stream = Stream([data])
            result = probe('fixture', 8080, connector=lambda *a, **k: stream, clock=stream.clock)
            self.assertFalse(result['admitted'])
            self.assertEqual(result['stage'], 'receive')
            self.assertEqual(result['error'], error)
            self.assertEqual(result['received_bytes'], len(data))

    def test_fragments_share_one_deadline_instead_of_refreshing_timeout(self):
        clock = Clock()
        stream = Stream([PAYLOAD[:3], PAYLOAD[3:6], PAYLOAD[6:]], clock, delay=0.04)
        result = probe('fixture', 8080, 0.1, connector=lambda *a, **k: stream, clock=clock)
        self.assertFalse(result['admitted'])
        self.assertEqual(result['error'], 'TimeoutError')
        self.assertEqual(result['received_bytes'], 6)
        self.assertAlmostEqual(result['elapsed_ms'], 100)
        self.assertAlmostEqual(stream.timeouts[-1], 0.02)

    def test_connect_time_uses_the_same_deadline(self):
        clock = Clock()
        stream = Stream([PAYLOAD], clock, delay=0.04)

        def connect(*_, **__):
            clock.now += 0.08
            return stream

        result = probe('fixture', 8080, 0.1, connector=connect, clock=clock)
        self.assertFalse(result['admitted'])
        self.assertAlmostEqual(result['elapsed_ms'], 100)

    def test_connection_error_is_recorded_without_retry(self):
        calls = []

        def connect(*args, **kwargs):
            calls.append((args, kwargs))
            raise ConnectionRefusedError(errno.ECONNREFUSED, 'fixture')

        result = probe('fixture', 8080, connector=connect)
        self.assertFalse(result['admitted'])
        self.assertEqual(result['stage'], 'connect')
        self.assertEqual(result['error'], 'ConnectionRefusedError')
        self.assertEqual(result['errno'], errno.ECONNREFUSED)
        self.assertEqual(len(calls), 1)

    def test_stream_reset_retains_partial_receive_diagnostics(self):
        stream = Stream([PAYLOAD[:4], ConnectionResetError(errno.ECONNRESET, 'fixture')])
        result = probe('fixture', 8080, connector=lambda *a, **k: stream, clock=stream.clock)
        self.assertFalse(result['admitted'])
        self.assertEqual(result['received_bytes'], 4)
        self.assertEqual(result['errno'], errno.ECONNRESET)

    def test_established_stream_failures_still_raise_for_revocation_assertions(self):
        with self.assertRaises(EchoFailure):
            echo(Stream([]))


if __name__ == '__main__':
    unittest.main()
