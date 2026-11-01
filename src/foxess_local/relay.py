"""FoxESS dongle TLS relay — intercept, log, and forward traffic.

Accepts TLS connections from the dongle on the configured port,
forwards to the real FoxESS monitor server, and stores all frames
in a SQLite database.

The server never stops — individual connection errors are logged
and the relay continues accepting new connections.

Configure via environment variables (see .env.example).
"""

import asyncio
import concurrent.futures
import datetime
import logging
import os
import pathlib
import ssl
import traceback

from foxess_local.store import open_db, insert_frame

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("FOXESS_UPSTREAM_PORT", "14431"))
UPSTREAM_HOST = os.environ.get("FOXESS_UPSTREAM_HOST", "8.209.116.72")
UPSTREAM_PORT = int(os.environ.get("FOXESS_UPSTREAM_PORT", "14431"))

PROJECT_ROOT = pathlib.Path(__file__).parent.parent.parent
CERT_FILE = PROJECT_ROOT / "certs" / "server.pem"
KEY_FILE = PROJECT_ROOT / "certs" / "server.key"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("foxess.relay")

# Single-threaded executor serialises all DB writes.
# The _db connection is only accessed from this one executor thread.
_db_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="db")
_db = None


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


def _write_frame(direction: str, data: bytes) -> None:
    """Synchronous DB write — runs in the single-threaded db executor."""
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        insert_frame(_db, ts, direction, data)
    except Exception:
        log.error("DB write failed: %s", traceback.format_exc())


async def relay(
    label: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    direction: str,
):
    """Copy bytes from reader to writer, storing each frame in the database."""
    loop = asyncio.get_running_loop()
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
            # DB write is best-effort; forwarding is critical
            loop.run_in_executor(_db_executor, _write_frame, direction, data)
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

    try:
        upstream_ctx = make_upstream_ssl_ctx()
        up_reader, up_writer = await asyncio.open_connection(
            UPSTREAM_HOST, UPSTREAM_PORT, ssl=upstream_ctx
        )
        log.info("Connected to upstream %s:%s", UPSTREAM_HOST, UPSTREAM_PORT)

        t1 = asyncio.create_task(
            relay("dongle→cloud", client_reader, up_writer, "c2s")
        )
        t2 = asyncio.create_task(
            relay("cloud→dongle", up_reader, client_writer, "s2c")
        )
        await asyncio.gather(t1, t2, return_exceptions=True)

    except Exception as e:
        log.error("Connection handler error: %s", e)

    finally:
        log.info("Connection closed from %s", peer)
        try:
            client_writer.close()
        except Exception:
            pass


async def _run():
    global _db
    _db = open_db()
    log.info("Database: %s", _db.execute("PRAGMA database_list").fetchone()[2])

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
    finally:
        if _db:
            _db.close()
        _db_executor.shutdown(wait=True)


if __name__ == "__main__":
    main()
