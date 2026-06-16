#!/usr/bin/env python3
"""Run fanything-ssh.nse against a deterministic local SSH test server."""

from __future__ import annotations

import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NSE = Path(os.environ.get("NSE", ROOT / "fanything-ssh.nse"))
HOST = os.environ.get("HOST", "127.0.0.1")
BASE_PORT = int(os.environ.get("BASE_PORT", "0"))
BANNER = b"SSH-2.0-TestSSH_1.0\r\n"


def name_list(value: str) -> bytes:
    data = value.encode("ascii")
    return struct.pack(">I", len(data)) + data


def kexinit_packet() -> bytes:
    lists = [
        "curve25519-sha256,ecdh-sha2-nistp256",
        "rsa-sha2-512,rsa-sha2-256,ssh-ed25519",
        "chacha20-poly1305@openssh.com,aes128-ctr",
        "chacha20-poly1305@openssh.com,aes128-ctr",
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    ]
    payload = b"\x14" + (b"\x00" * 16) + b"".join(name_list(v) for v in lists)
    payload += b"\x00" + struct.pack(">I", 0)

    pad_len = 4
    while (4 + 1 + len(payload) + pad_len) % 8 != 0:
        pad_len += 1
    packet_len = 1 + len(payload) + pad_len
    return struct.pack(">IB", packet_len, pad_len) + payload + (b"\x00" * pad_len)


def read_line(conn: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n") and len(data) < 512:
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def serve(server: socket.socket, stop: threading.Event) -> None:
    packet = kexinit_packet()
    server.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        with conn:
            conn.settimeout(2)
            try:
                client_banner = read_line(conn)
                if client_banner.startswith(b"SSH-"):
                    conn.sendall(BANNER + packet)
                    time.sleep(0.1)
            except OSError:
                pass


def main() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, BASE_PORT))
        server.listen(8)
        port = server.getsockname()[1]

        stop = threading.Event()
        thread = threading.Thread(target=serve, args=(server, stop), daemon=True)
        thread.start()

        cmd = [
            "nmap",
            "-Pn",
            "-p",
            str(port),
            "--script",
            str(NSE),
            "--script-args",
            "fanything-ssh.force=true",
            HOST,
        ]
        proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)
        stop.set()
        thread.join(timeout=1)

    output = proc.stdout + proc.stderr
    checks = [
        "mode: active",
        "protocol: ssh",
        "role: peer",
        "fingerprint: fan1:ssh:peer:active:",
        "features: ssh|peer|id=TestSSH_1.0|kex=curve25519-sha256,ecdh-sha2-nistp256",
        "|hostkey=rsa-sha2-512,rsa-sha2-256,ssh-ed25519|",
        "|enc_c2s=chacha20-poly1305@openssh.com,aes128-ctr|",
        "|mac_c2s=hmac-sha2-256|mac_s2c=hmac-sha2-256|",
        "|comp_c2s=none|comp_s2c=none|lang_c2s=|lang_s2c=|follows=False",
    ]
    missing = [check for check in checks if check not in output]
    if proc.returncode != 0 or missing or "ssh|peer|active|" in output:
        sys.stderr.write(output)
        if missing:
            sys.stderr.write("missing checks:\n" + "\n".join(missing) + "\n")
        if "ssh|peer|active|" in output:
            sys.stderr.write("feature string still contains active mode\n")
        return 1

    for line in output.splitlines():
        stripped = line.strip(" |_")
        if stripped.startswith("features:") or stripped.startswith("fingerprint:"):
            print(stripped)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
