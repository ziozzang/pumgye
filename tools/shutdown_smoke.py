#!/usr/bin/env python3
"""Qualify actual SIGTERM against an isolated loopback authority."""
import argparse
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/pumgye'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix='pumgye-sigterm-') as directory:
        state = Path(directory)
        http, native, ready = free_port(), free_port(), free_port()
        env = dict(os.environ,
                   PUMGYE_ADMIN_TOKEN='owned-admin-token-at-least-thirty-two-bytes',
                   PUMGYE_DECISION_TOKEN='owned-decision-token-at-least-thirty-two-bytes')
        with (state / 'server.log').open('wb') as log:
            process = subprocess.Popen([
                str(binary), '--listen', f'127.0.0.1:{http}',
                '--decision-listen', f'127.0.0.1:{native}',
                '--readiness-listen', f'127.0.0.1:{ready}',
                '--database', str(state / 'state.db'),
                '--policy', str(root / 'examples/policy.json'),
            ], env=env, stdout=log, stderr=log)
            try:
                for _ in range(100):
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{http}/healthz', timeout=.2) as response:
                            assert response.status == 200
                        break
                    except Exception:
                        if process.poll() is not None:
                            raise RuntimeError('owned server exited before readiness')
                        time.sleep(.05)
                else:
                    raise RuntimeError('readiness timeout')
                with socket.create_connection(('127.0.0.1', native), timeout=1) as idle:
                    time.sleep(.05)
                    started = time.monotonic()
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=8) == 0
                    elapsed = time.monotonic() - started
                    idle.settimeout(1)
                    try:
                        assert idle.recv(1) == b''
                    except ConnectionResetError:
                        pass
                    assert elapsed < 7
                print(f'PASS: SIGTERM clean exit in {elapsed:.2f}s; idle native socket closed')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()
