# SNI-Spoofing

Bypass DPI (Deep Packet Inspection) with IP/TCP-header manipulation.

## How it works

The tool runs a local TCP proxy. For each incoming connection it:

1. Opens an outgoing TCP connection to the configured destination.
2. Uses [WinDivert](https://reqrypt.org/windivert.html) (via `pydivert`) to
   intercept the handshake and inject a **fake TLS ClientHello** carrying a
   decoy SNI.
3. Sends that fake packet with a deliberately **wrong TCP sequence number**
   (`wrong_seq` method). The DPI middlebox inspects it and sees the decoy SNI,
   while the real server silently discards the out-of-window segment.
4. Relays the real traffic afterwards, so your genuine SNI is never seen by the
   DPI in a way it can act on.

## Requirements

- **Windows** (WinDivert is Windows-only) with administrator privileges.
- **Python 3.9+**.
- `pydivert>=3.1.0` (installs the bundled WinDivert driver).

```bash
pip install -r requirements.txt
```

## Configuration

Edit `config.json`:

| Key           | Description                                              |
|---------------|----------------------------------------------------------|
| `LISTEN_HOST` | Local address the proxy listens on (e.g. `0.0.0.0`).     |
| `LISTEN_PORT` | Local port the proxy listens on (e.g. `40443`).          |
| `CONNECT_IP`  | Destination IP to tunnel to.                             |
| `CONNECT_PORT`| Destination port (usually `443`).                        |
| `FAKE_SNI`    | Decoy SNI shown to the DPI (max 219 bytes).              |

## Usage

Run **as administrator** (WinDivert needs it):

```bash
python main.py
```

Then point your client at `LISTEN_HOST:LISTEN_PORT`. The proxy prints the
active listen/connect configuration on startup.

Stop with `Ctrl+C`.

## Notes

- Only IPv4 destinations are currently wired up in `main.py`.
- The `wrong_seq` bypass method is the only one currently implemented.

---

حمایت کنید، کارهای بزرگی در دست انجام هست:

USDT (BEP20): `0x76a768B53Ca77B43086946315f0BDF21156bF424`

USDT (TRC20): `TU5gKvKqcXPn8itp1DouBCwcqGHMemBm8o`

- https://t.me/projectXhttp
- https://t.me/patterniha
