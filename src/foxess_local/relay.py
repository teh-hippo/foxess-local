"""FoxESS dongle TLS relay — intercept, log, and forward traffic.

Accepts TLS connections from the dongle on the configured port,
forwards to the real FoxESS monitor server, and logs all bytes
bidirectionally as JSON-lines.

The server never stops — individual connection errors are logged
and the relay continues accepting new connections.

Configure via environment variables (see .env.example).
"""

import asyncio
import datetime
import json
import logging
import os
import pathlib
import ssl
import traceback

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("FOXESS_UPSTREAM_PORT", "14431"))
UPSTREAM_HOST = os.environ.get("FOXESS_UPSTREAM_HOST", "47.91.86.144")
UPSTREAM_PORT = int(os.environ.get("FOXESS_UPSTREAM_PORT", "14431"))

PROJECT_ROOT = pathlib.Path(__file__).parent.parent.parent
CERT_FILE = PROJECT_ROOT / "certs" / "server.pem"
KEY_FILE = PROJECT_ROOT / "certs" / "server.key"
CAPTURE_DIR = PROJECT_ROOT / "captures"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("foxess.relay")


def make_server_ssl_ctx() -> ssl.SSLContext:
    """TLS context for accepting dongle connections."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT_FILE), str(KEY_FILE))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def make_upstream_ssl_ctx() -> ssl.SSLContext:
    """TLS context for connecting to the real FoxESS server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class CaptureLog:
    """Append-only JSON-lines capture file."""

    def __init__(self, path: pathlib.Path):
        self._f = open(path, "a")
        log.info("Capture log: %s", path)

    def write(self, direction: str, data: bytes):
        record = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "dir": direction,
            "len": len(data),
            "hex": data.hex(),
        }
        try:
            record["utf8"] = data.decode("utf-8", errors="replace")
        except Exception:
            pass
        self._f.write(json.dumps(record) + "\n")
        self._f.flush()

    def close(self):
        try:
            self._f.close()
        except Exception:
            pass


async def relay(
    label: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    capture: CaptureLog,
    direction: str,
):
    """Copy bytes from reader to writer, logging everything."""
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
            capture.write(direction, data)
            log.info("%s %s %d bytes", label, direction, len(data))
            writer.write(data)
            await writer.drain()
    except Exception as e:
        log.debug("relay %s ended: %s", label, e)
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
):
    peer = client_writer.get_extra_info("peername")
    log.info("New connection from %s", peer)

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    CAPTURE_DIR.mkdir(exist_ok=True)
    capture = CaptureLog(CAPTURE_DIR / f"capture_{ts}.jsonl")

    try:
        upstream_ctx = make_upstream_ssl_ctx()
        up_reader, up_writer = await asyncio.open_connection(
            UPSTREAM_HOST, UPSTREAM_PORT, ssl=upstream_ctx
        )
        log.info("Connected to upstream %s:%s", UPSTREAM_HOST, UPSTREAM_PORT)

        t1 = asyncio.create_task(
            relay("dongle→cloud", client_reader, up_writer, capture, "c2s")
        )
        t2 = asyncio.create_task(
            relay("cloud→dongle", up_reader, client_writer, capture, "s2c")
        )
        await asyncio.gather(t1, t2, return_exceptions=True)

    except Exception as e:
        log.error("Connection handler error: %s", e)

    finally:
        log.info("Connection closed from %s", peer)
        capture.close()
        try:
            client_writer.close()
        except Exception:
            pass


async def _run():
    server_ctx = make_server_ssl_ctx()
    server = await asyncio.start_server(
        handle_client,
        LISTEN_HOST,
        LISTEN_PORT,
        ssl=server_ctx,
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.info("Local proxy listening on %s", addrs)
    log.info("Upstream: %s:%s", UPSTREAM_HOST, UPSTREAM_PORT)
    log.info("Captures go to: %s/", CAPTURE_DIR)

    async with server:
        await server.serve_forever()


def main():
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        log.info("Shutting down")
    except Exception:
        log.critical("Fatal error:\n%s", traceback.format_exc())
        raise


if __name__ == "__main__":
    main()
