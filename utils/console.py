"""Beautiful, meaningful console UI for SNI-Spoofing.

This module is *purely presentational*. It does not touch the DPI-bypass core:
all packet manipulation, socket handling and the bypass logic live elsewhere
and are unchanged. Everything here exists to turn the operator's terminal into
something clear and pleasant instead of dumping raw packet objects and Python
tracebacks on every hiccup.

Design goals
------------
* A polished startup experience (banner, live configuration, support panel).
* Meaningful, human-readable log lines for the events that actually matter:
  a tunnel coming up, a tunnel closing, a real failure.
* No log spam. The old build printed a raw ``Packet`` repr for every anomalous
  segment the DPI/peer produced during a handshake. Those are now aggregated
  into counters and surfaced calmly, with full technical detail available on
  demand via the ``SNI_DEBUG=1`` environment variable.
* Thread-safe: the packet injector runs on its own thread, the relay runs on
  the asyncio loop. All output goes through a single lock-guarded console.

If ``rich`` is not installed the module degrades gracefully to plain ``print``
so the tool always runs.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from datetime import datetime, timedelta

APP_NAME = "SNI-SPOOFING"
APP_VERSION = "1.2"
TAGLINE = "Bypass Deep Packet Inspection · TCP/TLS header manipulation"

# Full technical detail (per-packet anomalies, tracebacks) is opt-in.
DEBUG = os.environ.get("SNI_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")

try:  # rich is the preferred renderer; fall back to plain text if unavailable.
    from rich.console import Console
    from rich.theme import Theme
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    from rich import box

    _RICH = True
except Exception:  # pragma: no cover - defensive fallback
    _RICH = False


# --------------------------------------------------------------------------- #
# Theme
# --------------------------------------------------------------------------- #

_THEME = {
    "brand": "bold cyan",
    "accent": "cyan",
    "muted": "grey58",
    "ok": "bold green",
    "okdim": "green",
    "warn": "yellow",
    "err": "bold red",
    "info": "bright_blue",
    "value": "bold white",
    "live": "bold green",
}


def _endpoint(addr) -> str:
    """Format a (host, port) tuple (or anything) as ``host:port``."""
    try:
        host, port = addr[0], addr[1]
        return f"{host}:{port}"
    except Exception:
        return str(addr)


def _friendly(reason: str | None) -> str:
    """Translate a terse internal anomaly string into plain language."""
    if not reason:
        return "connection interrupted during handshake"
    r = reason.lower()
    if "no syn sent" in r:
        return "unexpected reply before the handshake started"
    if "syn-ack" in r and ("seq" in r or "ack" in r):
        return "handshake reply didn't match (DPI/peer interference)"
    if "seq not matched" in r or "seq change" in r:
        return "TCP sequence mismatch (DPI/peer interference)"
    if "ack not matched" in r or "ack_num is not zero" in r:
        return "TCP acknowledgement mismatch (DPI/peer interference)"
    if "after fake sent" in r or "after fake" in r:
        return "peer answered after the decoy was injected"
    return "unexpected packet during handshake"


class _Stats:
    """Thread-safe session counters."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started_at = time.monotonic()
        self.total_tunnels = 0
        self.active = 0
        self.peak_active = 0
        self.failed_handshake = 0
        self.failed_connect = 0

    def open(self) -> tuple[int, int]:
        with self._lock:
            self.total_tunnels += 1
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)
            return self.total_tunnels, self.active

    def close(self) -> int:
        with self._lock:
            if self.active > 0:
                self.active -= 1
            return self.active

    def add_handshake_failure(self) -> int:
        with self._lock:
            self.failed_handshake += 1
            return self.failed_handshake

    def add_connect_failure(self) -> int:
        with self._lock:
            self.failed_connect += 1
            return self.failed_connect


class _UI:
    """Single entry point for all console output."""

    def __init__(self) -> None:
        self.stats = _Stats()
        self._lock = threading.Lock()
        if _RICH:
            self.console = Console(theme=Theme(_THEME), highlight=False, soft_wrap=False)
        else:
            self.console = None

    # -- low level ---------------------------------------------------------- #

    def _out(self, renderable, **kwargs) -> None:
        with self._lock:
            if self.console is not None:
                self.console.print(renderable, **kwargs)
            else:  # plain fallback
                print(renderable)

    def _log(self, icon: str, style: str, msg: str, detail: str | None = None) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        if self.console is not None:
            line = Text()
            line.append(f" {ts} ", style="muted")
            line.append(f"{icon} ", style=style)
            line.append(msg, style=style if style in ("ok", "err") else "value")
            if detail:
                line.append(f"  {detail}", style="muted")
            # Log lines behave like a stream: let the terminal wrap visually
            # rather than hard-breaking mid-token.
            self._out(line, soft_wrap=True)
        else:
            extra = f"  {detail}" if detail else ""
            self._out(f" {ts} {icon} {msg}{extra}")

    # -- public: informational log levels ----------------------------------- #

    def info(self, msg: str, detail: str | None = None) -> None:
        self._log("•", "info", msg, detail)

    def success(self, msg: str, detail: str | None = None) -> None:
        self._log("✓", "ok", msg, detail)

    def warn(self, msg: str, detail: str | None = None) -> None:
        self._log("▲", "warn", msg, detail)

    def error(self, msg: str, detail: str | None = None) -> None:
        self._log("✗", "err", msg, detail)

    def debug(self, msg: str, detail: str | None = None) -> None:
        if DEBUG:
            self._log("·", "muted", msg, detail)

    # -- public: startup ---------------------------------------------------- #

    def banner(self) -> None:
        if self.console is None:
            self._out(f"\n=== {APP_NAME} v{APP_VERSION} ===\n{TAGLINE}\n")
            return
        title = Text(justify="center")
        title.append(f"{APP_NAME}", style="brand")
        title.append(f"  v{APP_VERSION}\n", style="muted")
        title.append(TAGLINE, style="accent")
        self._out(Text())
        self._out(
            Panel(
                Align.center(title),
                box=box.DOUBLE,
                border_style="accent",
                padding=(1, 4),
            )
        )

    def online(
        self,
        listen_host: str,
        listen_port: int,
        connect_ip: str,
        connect_port: int,
        fake_sni: str,
        interface: str,
        method: str,
        data_mode: str = "tls",
    ) -> None:
        """Render the active configuration and the LIVE status line."""
        if self.console is None:
            self._out(
                f"Listening on {listen_host}:{listen_port} -> "
                f"{connect_ip}:{connect_port} "
                f"(fake SNI: {fake_sni}, via {interface})"
            )
            self._out("LIVE — waiting for connections...\n")
            return

        table = Table.grid(padding=(0, 2))
        table.add_column(justify="right", style="muted", no_wrap=True)
        table.add_column(style="value")
        table.add_row("Listen", f"{listen_host}:{listen_port}")
        table.add_row("Forward", f"→  {connect_ip}:{connect_port}")
        table.add_row("Fake SNI", fake_sni)
        table.add_row("Interface", interface)
        table.add_row("Method", f"{method}  ·  {data_mode.upper()}")
        self._out(
            Panel(
                table,
                title="[muted]configuration[/]",
                title_align="left",
                box=box.ROUNDED,
                border_style="muted",
                padding=(1, 2),
            )
        )
        status = Text()
        status.append("  ● ", style="live")
        status.append("LIVE", style="live")
        status.append("  —  waiting for connections…", style="muted")
        self._out(status)
        self._out(Text())

    def support(self) -> None:
        if self.console is None:
            self._out(
                "If this tool helps you reach the free internet, please consider "
                "supporting the project.\nUSDT (BEP20): "
                "0x76a768B53Ca77B43086946315f0BDF21156bF424\n"
                "Telegram: @patterniha  ·  @projectXhttp\n"
            )
            return
        body = Text()
        body.append("If this tool helps you reach the free internet, please consider supporting it.\n", style="value")
        body.append("More free-internet projects are on the way and need your support.\n\n", style="muted")
        body.append("USDT (BEP20)  ", style="muted")
        body.append("0x76a768B53Ca77B43086946315f0BDF21156bF424\n", style="accent")
        body.append("Telegram      ", style="muted")
        body.append("@patterniha", style="accent")
        body.append("  ·  ", style="muted")
        body.append("@projectXhttp", style="accent")
        self._out(
            Panel(
                body,
                title="[brand]Support this project[/]",
                title_align="left",
                box=box.ROUNDED,
                border_style="accent",
                padding=(1, 2),
            )
        )

    # -- public: connection lifecycle -------------------------------------- #

    def tunnel_up(self, client_addr, dest) -> None:
        total, active = self.stats.open()
        self.success(
            f"tunnel established  {_endpoint(client_addr)}  →  {_endpoint(dest)}",
            detail=f"active {active} · total {total}",
        )

    def tunnel_down(self, client_addr, dest) -> None:
        active = self.stats.close()
        # Normal teardown is quiet by default; visible in debug mode.
        self.debug(
            f"tunnel closed       {_endpoint(client_addr)}  →  {_endpoint(dest)}",
            detail=f"active {active}",
        )

    def connect_failed(self, dest, error: str | None = None) -> None:
        """Could not even open the outbound TCP connection to the destination."""
        n = self.stats.add_connect_failure()
        if DEBUG:
            self.error(f"could not reach {_endpoint(dest)}", detail=error)
        elif n == 1 or n % 20 == 0:
            self.warn(
                f"can't reach destination {_endpoint(dest)}",
                detail=f"{n} failed so far — check CONNECT_IP / network",
            )

    def handshake_failed(self, dest=None, reason: str | None = None) -> None:
        """The DPI/peer interfered with the spoofed handshake for one connection.

        These are per-connection and, in a hostile network, can happen often.
        We aggregate them instead of dumping a raw packet for each one.
        """
        n = self.stats.add_handshake_failure()
        if DEBUG:
            self.warn(
                f"handshake interrupted → {_endpoint(dest) if dest else '?'}",
                detail=f"{_friendly(reason)}  [{reason}]",
            )
        elif n == 1 or n % 25 == 0:
            self.warn(
                f"{n} handshake attempt(s) interrupted by network/DPI",
                detail="the client will simply retry — this is usually harmless",
            )

    # -- public: shutdown --------------------------------------------------- #

    def shutdown(self) -> None:
        uptime = timedelta(seconds=int(time.monotonic() - self.stats.started_at))
        s = self.stats
        if self.console is None:
            self._out(
                f"\nShutting down. uptime {uptime} · tunnels {s.total_tunnels} · "
                f"peak {s.peak_active} · handshake-fails {s.failed_handshake} · "
                f"connect-fails {s.failed_connect}\n"
            )
            return
        table = Table.grid(padding=(0, 2))
        table.add_column(justify="right", style="muted", no_wrap=True)
        table.add_column(style="value")
        table.add_row("Uptime", str(uptime))
        table.add_row("Tunnels served", str(s.total_tunnels))
        table.add_row("Peak concurrent", str(s.peak_active))
        table.add_row("Handshakes interrupted", str(s.failed_handshake))
        table.add_row("Unreachable attempts", str(s.failed_connect))
        self._out(Text())
        self._out(
            Panel(
                table,
                title="[brand]session summary[/]",
                subtitle="[muted]goodbye[/]",
                title_align="left",
                box=box.ROUNDED,
                border_style="accent",
                padding=(1, 2),
            )
        )


# Module-level singleton used across the app.
ui = _UI()


def silence_event_loop_noise(loop) -> None:
    """Stop asyncio from spamming the console with benign teardown tracebacks.

    On Windows the default (proactor) event loop cannot cleanly cancel a pending
    overlapped operation once we close a socket at end-of-stream. It reports this
    via ``call_exception_handler`` as::

        Cancelling an overlapped future failed
        OSError: [WinError 6] The handle is invalid
        ValueError: eof   (from the relay loop's normal end-of-stream)

    None of this indicates a real problem — it is just a connection closing — but
    the loop prints a full traceback for every closed tunnel, which is exactly the
    noise we want gone. This installs a handler that drops those benign events
    (visible only when ``SNI_DEBUG=1``) while still surfacing anything genuinely
    unexpected as a single concise line. It changes only how errors are *reported*;
    the DPI-bypass core is untouched.
    """

    _BENIGN_MARKERS = (
        "overlapped",              # "Cancelling an overlapped future failed"
        "handle is invalid",       # WinError 6
        "winerror 6",
        "eof",                     # relay loop's normal end-of-stream ValueError
        "connection reset",
        "connection aborted",
        "broken pipe",
    )

    def _handler(loop, context):
        message = context.get("message", "")
        exc = context.get("exception")
        blob = f"{message} {exc!r}".lower()
        if any(marker in blob for marker in _BENIGN_MARKERS):
            ui.debug("asyncio teardown (benign)", detail=message or repr(exc))
            return
        if DEBUG:
            loop.default_exception_handler(context)
        else:
            ui.error("internal event-loop error", detail=message or repr(exc))

    loop.set_exception_handler(_handler)
