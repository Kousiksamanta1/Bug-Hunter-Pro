"""Lightweight HTTP and DNS callback receiver."""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import socket
import socketserver
import struct
import threading
from urllib.parse import parse_qs, urlparse
import uuid

import config
from database import models


LOGGER = logging.getLogger(__name__)


class _ReusableHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


class _ReusableUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class CallbackServer:
    def __init__(self):
        self.http_server = None
        self.dns_server = None
        self.http_thread = None
        self.dns_thread = None
        self.http_port = None
        self.dns_port = None
        self._lock = threading.RLock()

    def start(self, http_port=8888, dns_port=5353):
        with self._lock:
            if self.is_running():
                return self.get_callback_url()
            owner = self

            class HTTPHandler(BaseHTTPRequestHandler):
                def log_message(self, format_string, *args):
                    LOGGER.debug(format_string, *args)

                def do_GET(self):
                    self._record()

                def do_POST(self):
                    self._record()

                def do_PUT(self):
                    self._record()

                def _record(self):
                    length = min(int(self.headers.get("Content-Length", "0") or 0), 1_000_000)
                    body = self.rfile.read(length).decode("utf-8", errors="replace")
                    parsed = urlparse(self.path)
                    values = parse_qs(parsed.query)
                    extracted = {
                        name: values.get(name, [""])[0]
                        for name in ("c", "d", "u", "h", "event")
                        if name in values
                    }
                    callback = {
                        "id": str(uuid.uuid4()),
                        "callback_type": "http",
                        "source_ip": self.client_address[0],
                        "path": self.path,
                        "headers": json.dumps(dict(self.headers), default=str),
                        "body": body,
                        "data": json.dumps(extracted),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    models.insert_oob_callback(callback)
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()

            class DNSHandler(socketserver.BaseRequestHandler):
                def handle(self):
                    packet, sock = self.request
                    qname, question_end = owner._parse_dns_question(packet)
                    callback = {
                        "id": str(uuid.uuid4()),
                        "callback_type": "dns",
                        "source_ip": self.client_address[0],
                        "path": qname,
                        "headers": "",
                        "body": "",
                        "data": json.dumps({"qname": qname, "qtype": "A"}),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    models.insert_oob_callback(callback)
                    response = owner._dns_response(packet, question_end)
                    if response:
                        sock.sendto(response, self.client_address)

            try:
                self.http_server = _ReusableHTTPServer(
                    ("0.0.0.0", int(http_port)),
                    HTTPHandler,
                )
                self.dns_server = _ReusableUDPServer(
                    ("0.0.0.0", int(dns_port)),
                    DNSHandler,
                )
            except OSError:
                for server in (self.http_server, self.dns_server):
                    if server:
                        server.server_close()
                self.http_server = None
                self.dns_server = None
                raise
            self.http_port = int(self.http_server.server_address[1])
            self.dns_port = int(self.dns_server.server_address[1])
            self.http_thread = threading.Thread(
                target=self.http_server.serve_forever,
                name="bughunter-oob-http",
                daemon=True,
            )
            self.dns_thread = threading.Thread(
                target=self.dns_server.serve_forever,
                name="bughunter-oob-dns",
                daemon=True,
            )
            self.http_thread.start()
            self.dns_thread.start()
            return self.get_callback_url()

    def stop(self):
        with self._lock:
            for server in (self.http_server, self.dns_server):
                if server:
                    server.shutdown()
                    server.server_close()
            self.http_server = None
            self.dns_server = None
            self.http_thread = None
            self.dns_thread = None
            self.http_port = None
            self.dns_port = None

    @staticmethod
    def _parse_dns_question(packet):
        if len(packet) < 13:
            return "", 0
        labels = []
        offset = 12
        while offset < len(packet):
            length = packet[offset]
            offset += 1
            if length == 0:
                break
            if offset + length > len(packet):
                return "", 0
            labels.append(packet[offset:offset + length].decode("ascii", errors="ignore"))
            offset += length
        question_end = offset + 4
        return ".".join(labels), question_end

    @staticmethod
    def _dns_response(packet, question_end):
        if question_end <= 0 or question_end > len(packet):
            return b""
        transaction = packet[:2]
        flags = b"\x81\x80"
        counts = struct.pack("!HHHH", 1, 1, 0, 0)
        question = packet[12:question_end]
        answer = (
            b"\xc0\x0c"
            + struct.pack("!HHI", 1, 1, 30)
            + struct.pack("!H", 4)
            + socket.inet_aton("0.0.0.0")
        )
        return transaction + flags + counts + question + answer

    def get_callbacks(self, since=None):
        return models.get_oob_callbacks(since)

    def get_callback_url(self):
        host = self._local_ip()
        port = self.http_port or config.OOB_HTTP_PORT
        return f"http://{host}:{port}"

    def get_dns_host(self):
        return self._local_ip()

    def is_running(self):
        return bool(
            self.http_server
            and self.dns_server
            and self.http_thread
            and self.http_thread.is_alive()
            and self.dns_thread
            and self.dns_thread.is_alive()
        )

    @staticmethod
    def _local_ip():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"
        finally:
            sock.close()


callback_server = CallbackServer()
