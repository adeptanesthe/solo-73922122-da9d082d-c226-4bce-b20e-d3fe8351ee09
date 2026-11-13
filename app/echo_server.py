"""附带的 HTTP 回显服务（标准库实现，无第三方依赖）。

对任意请求返回 JSON 形式的请求回显，用于验证该端口是否在白名单内：
端口被放行时 curl 可通；被移出白名单后（已有连接也会被丢弃）请求挂死/失败，
回退恢复后再次可通。
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from config import ECHO_PORT


class EchoHandler(BaseHTTPRequestHandler):
    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        payload = {
            "service": "http-echo",
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
            "body": body.decode("utf-8", errors="replace"),
            "client": self.client_address[0],
        }
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle

    def log_message(self, fmt: str, *args) -> None:  # 安静一点
        threading.current_thread().name = "echo-worker"
        print(f"[echo] {self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", ECHO_PORT), EchoHandler)
    print(f"[echo] HTTP 回显服务监听 0.0.0.0:{ECHO_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
