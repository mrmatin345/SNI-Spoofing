import asyncio
import os
import socket
import sys
import traceback
import threading
import json

# from utils.proxy_protocols import parse_vless_protocol
from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector

# Buffer size used for socket reads. Slightly above the 65535 max TCP payload
# so a full segment plus a little slack always fits in one recv.
RECV_BUFFER_SIZE = 65575


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, 'frozen', False):
        # Running as a PyInstaller EXE
        return os.path.dirname(sys.executable)
    else:
        # Running as a normal Python script
        return os.path.dirname(os.path.abspath(__file__))


def load_config(path):
    """Load and validate config.json, exiting with a clear message on error."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except FileNotFoundError:
        sys.exit("config.json not found at: " + path)
    except json.JSONDecodeError as e:
        sys.exit("config.json is not valid JSON: " + str(e))

    required = ("LISTEN_HOST", "LISTEN_PORT", "CONNECT_IP", "CONNECT_PORT", "FAKE_SNI")
    missing = [k for k in required if k not in cfg]
    if missing:
        sys.exit("config.json is missing required keys: " + ", ".join(missing))

    for port_key in ("LISTEN_PORT", "CONNECT_PORT"):
        port = cfg[port_key]
        if not isinstance(port, int) or not (0 < port < 65536):
            sys.exit(port_key + " must be an integer between 1 and 65535, got: " + repr(port))

    fake_sni = cfg["FAKE_SNI"]
    if not isinstance(fake_sni, str) or not fake_sni:
        sys.exit("FAKE_SNI must be a non-empty string.")
    # The ClientHello template has a fixed size; the SNI shares a 219-byte
    # budget with the trailing padding extension (see packet_templates.py).
    fake_sni_len = len(fake_sni.encode())
    if fake_sni_len > 219:
        sys.exit("FAKE_SNI is too long (max 219 bytes), got: " + str(fake_sni_len))

    return cfg


def set_tcp_keepalive(sock: socket.socket):
    """Enable TCP keep-alive, guarding options that are not available on every
    platform/Python build (TCP_KEEPIDLE/INTVL/CNT have limited Windows support)."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for opt_name, value in (("TCP_KEEPIDLE", 11), ("TCP_KEEPINTVL", 2), ("TCP_KEEPCNT", 3)):
        opt = getattr(socket, opt_name, None)
        if opt is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, opt, value)
        except (OSError, AttributeError):
            # Option not supported on this platform; keep-alive still works
            # with the OS defaults.
            pass


# Build the path to config.json and load it
config_path = os.path.join(get_exe_dir(), 'config.json')
config = load_config(config_path)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
FAKE_SNI = config["FAKE_SNI"].encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]
INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
if not INTERFACE_IPV4:
    sys.exit(
        "Could not determine the local IPv4 interface used to reach "
        + CONNECT_IP + ". Check your network connection and CONNECT_IP in config.json."
    )
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

##################

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}


def _drop_connection(conn: FakeInjectiveConnection):
    """Stop monitoring a connection and remove it from the registry (idempotent)."""
    conn.monitor = False
    fake_injective_connections.pop(conn.id, None)


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, peer_task: asyncio.Task):
    loop = asyncio.get_running_loop()
    while True:
        try:
            data = await loop.sock_recv(sock_1, RECV_BUFFER_SIZE)
            if not data:
                raise ValueError("eof")
            # sock_sendall() sends the whole buffer or raises; it returns None.
            await loop.sock_sendall(sock_2, data)
        except Exception:
            sock_1.close()
            sock_2.close()
            peer_task.cancel()
            return


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    outgoing_sock = None
    fake_injective_conn = None
    try:
        loop = asyncio.get_running_loop()

        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI,
                                                               os.urandom(32))
        else:
            sys.exit("impossible mode!")
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((INTERFACE_IPV4, 0))
        set_tcp_keepalive(outgoing_sock)
        src_port = outgoing_sock.getsockname()[1]
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, INTERFACE_IPV4, CONNECT_IP, src_port, CONNECT_PORT,
                                                      fake_data,
                                                      BYPASS_METHOD, incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        try:
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except Exception:
            _drop_connection(fake_injective_conn)
            outgoing_sock.close()
            incoming_sock.close()
            return

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    raise ValueError("unexpected close")
                if fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                    pass
                else:
                    sys.exit("impossible t2a msg!")
            except Exception:
                _drop_connection(fake_injective_conn)
                outgoing_sock.close()
                incoming_sock.close()
                return
        else:
            sys.exit("unknown bypass method!")

        _drop_connection(fake_injective_conn)

        oti_task = asyncio.create_task(
            relay_main_loop(outgoing_sock, incoming_sock, asyncio.current_task()))
        await relay_main_loop(incoming_sock, outgoing_sock, oti_task)

    except asyncio.CancelledError:
        # Normal teardown when the peer relay direction closes first.
        raise
    except Exception:
        traceback.print_exc()
        # A single connection failing must not take down the whole proxy.
        if fake_injective_conn is not None:
            _drop_connection(fake_injective_conn)
        if outgoing_sock is not None:
            outgoing_sock.close()
        incoming_sock.close()


async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    except OSError as e:
        mother_sock.close()
        sys.exit(
            "Could not bind to " + LISTEN_HOST + ":" + str(LISTEN_PORT)
            + " (" + str(e) + "). Is the port already in use or the address invalid?"
        )
    set_tcp_keepalive(mother_sock)
    mother_sock.listen()
    loop = asyncio.get_running_loop()
    print("Listening on " + LISTEN_HOST + ":" + str(LISTEN_PORT)
          + " -> " + CONNECT_IP + ":" + str(CONNECT_PORT)
          + " (fake SNI: " + FAKE_SNI.decode() + ", via " + INTERFACE_IPV4 + ")")
    try:
        while True:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
            incoming_sock.setblocking(False)
            set_tcp_keepalive(incoming_sock)
            asyncio.create_task(handle(incoming_sock, addr))
    finally:
        mother_sock.close()


if __name__ == "__main__":
    # Only divert the proxy's own flows to CONNECT_IP:CONNECT_PORT. Constraining
    # the capture to the destination port keeps WinDivert from intercepting (and
    # having to re-inject) unrelated TCP traffic to the same host.
    w_filter = ("tcp and ("
                "(ip.SrcAddr == " + INTERFACE_IPV4 + " and ip.DstAddr == " + CONNECT_IP
                + " and tcp.DstPort == " + str(CONNECT_PORT) + ")"
                " or "
                "(ip.SrcAddr == " + CONNECT_IP + " and ip.DstAddr == " + INTERFACE_IPV4
                + " and tcp.SrcPort == " + str(CONNECT_PORT) + ")"
                ")")
    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
    print("اگر از این برنامه برای دسترسی به اینترنت آزاد استفاده می‌کنید، حمایت فراموش نشه")
    print("پروژه‌ها و برنامه‌های زیادی برای دسترسی تمام مردم ایران به اینترنت آزاد در نظر دارم که به حمایت شما نیاز دارد")
    print("\n")
    print("USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424\n")
    print("@patterniha")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down.")
