"""Round-trip tests for the pure (WinDivert-free) TLS template helpers.

These cover byte-layout logic only, so they run on any platform without the
WinDivert driver. Run with:

    python -m pytest tests/            # if pytest is installed
    python tests/test_packet_templates.py   # plain-stdlib fallback
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.packet_templates import ClientHelloMaker, ServerHelloMaker  # noqa: E402


def test_client_hello_is_always_517_bytes():
    for sni_len in (1, 6, 15, 100, 219):
        ch = ClientHelloMaker.get_client_hello_with(
            os.urandom(32), os.urandom(32), b"a" * sni_len, os.urandom(32)
        )
        assert len(ch) == 517, (sni_len, len(ch))


def test_client_hello_round_trip():
    for sni in (b"a", b"mci.ir", b"auth.vercel.com", b"x" * 219):
        rnd, sess_id, key_share = os.urandom(32), os.urandom(32), os.urandom(32)
        ch = ClientHelloMaker.get_client_hello_with(rnd, sess_id, sni, key_share)
        r2, s2, sni2, ks2 = ClientHelloMaker.parse_client_hello(ch)
        assert (r2, s2, sni2, ks2) == (rnd, sess_id, sni.decode(), key_share)


def test_client_hello_rejects_oversized_sni():
    try:
        ClientHelloMaker.get_client_hello_with(
            os.urandom(32), os.urandom(32), b"x" * 220, os.urandom(32)
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError for SNI longer than 219 bytes")


def test_client_response_round_trip_including_short_payloads():
    # Regression guard: the header is 11 bytes, so responses shorter than 32
    # bytes (previously rejected by a wrong assertion) must round-trip.
    for app_data in (b"", b"hello", os.urandom(5), os.urandom(100)):
        resp = ClientHelloMaker.get_client_response_with(app_data)
        assert ClientHelloMaker.parse_client_response(resp) == app_data


def test_server_hello_round_trip():
    rnd, sess_id, key_share, app_data = (
        os.urandom(32), os.urandom(32), os.urandom(32), os.urandom(50),
    )
    sh = ServerHelloMaker.get_server_hello_with(rnd, sess_id, key_share, app_data)
    r2, s2, ks2, a2 = ServerHelloMaker.parse_server_hello(sh)
    assert (r2, s2, ks2, a2) == (rnd, sess_id, key_share, app_data)


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print("FAIL", name, "->", repr(exc))
    sys.exit(1 if failures else 0)
