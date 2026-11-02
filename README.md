# ZKTeco Security PUSH / ADMS — Python Server

A **standard-library-only Python diagnostic HTTP receiver** for investigating ZKTeco access-control devices using **Security PUSH / ADMS**. Designed to solve a common issue: the device connects and registers repeatedly, but does not send RFID card-scan events.

> **Status:** field-tested diagnostic prototype, **not** a hardened production access-control server. Verified on a **ZKTeco U1000 Pro, AC firmware 4.7.8.3033**, with `pushver=3.1.1` and device-reported `PushVersion=3.2.3.003`. Other models have not been verified.

## Features

- Handles `GET /iclock/cdata?options=all` during initialization.
- Handles `POST /iclock/registry`, generating and persisting a `RegistryCode`.
- **Handles `GET /iclock/push`** (and POST), providing the configuration needed to complete registration.
- Replies `OK` to `GET /iclock/getrequest` when no commands are queued.
- Receives `POST /iclock/cdata?table=rtlog`, `rtstate` and additional event uploads.
- Parses tab-separated `key=value` Security PUSH events with `cardno`, `pin`, `event`, `verifytype`, and `index`.
- Journals exact received payloads before sending acknowledgement, including unknown payload formats.
- Does **not** send device settings-write commands, unlock doors, control barriers, or change Wiegand configurations.

## Installation / Raspberry Pi quick start

Requires **Python 3.9+**. No third-party dependencies.

```bash
git clone https://github.com/0xa9u/zkteco-security-push-adms-python.git
cd zkteco-security-push-adms-python

python3 -u zkteco_push_probe.py \
  --host 0.0.0.0 \
  --port 6000 \
  --allowed-ip 192.0.2.20 \
  --serial YOUR_DEVICE_SERIAL \
  --mode security \
  --output ./zkteco_requests.jsonl \
  --state ./zkteco_registration_state.json
```

Replace `192.0.2.20` with the device's actual local IP and `YOUR_DEVICE_SERIAL` with the device serial. Configure the device's PUSH/ADMS server address to the Raspberry Pi's IP and port **6000**. The default bind address is `127.0.0.1`; `--host 0.0.0.0` is required for LAN clients.

**Do not expose the server to the public internet.** Use a trusted, isolated LAN and restrict access with `--allowed-ip` and a firewall. If the device has only one PUSH destination, testing here will temporarily redirect uploads away from the original server.

## The Security PUSH handshake that worked

```text
DEVICE                                         PYTHON SERVER
GET  /iclock/cdata?SN=...&options=all          200 OK (not registered)
POST /iclock/registry?SN=...                   200 RegistryCode=<persistent code>
GET  /iclock/push?SN=...                       200 application/push configuration
                                               TransTables=User Transaction
                                               Realtime=1
                                               SessionID=<persistent ID>
GET  /iclock/getrequest?SN=...                 200 OK (no commands)
POST /iclock/cdata?SN=...&table=rtlog          200 OK after journal write
POST /iclock/cdata?SN=...&table=rtstate        200 OK after journal write
```

**The critical fix was implementing `/iclock/push`.** A missing handler produced a recurring loop: register → GET `/iclock/push` → HTTP 404 → register again. Once the server returned the configuration block, the tested reader uploaded `rtlog` events, including RFID credentials with `pin=0`.

### Example event (synthetic)

```text
time=2026-01-01 12:00:00	pin=0	cardno=1a2b3	eventaddr=1	event=27	inoutstatus=0	verifytype=4	index=42
```

The raw `cardno` may be present without an enrolled user ID. Preserve the card number exactly as received. The meanings of `event=27` and `verifytype=4` should be checked against the target firmware before decisions are made. Neither an event nor an RFID value alone grants access.

The reader also uploads `rtstate` controller-state records and status `rtlog` events with an empty `cardno`.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

See [Troubleshooting](docs/TROUBLESHOOTING.md) for registration loops, missing card events, port conflicts and safe network captures.

## Security, privacy and limitations

- **Diagnostic only:** no secure-exchange cryptography, full session authentication, production access-control policy, or complete PUSH command implementation.
- Responses advertise protocol parameters; this is not equivalent to an authenticated server/device relationship.
- Journals include original request bodies in Base64 and text, potentially containing RFID credentials, personal information and secrets. Never commit journals, registration state, captured packets or unredacted logs.
- `.gitignore` excludes `*.jsonl`, `*.pcap`, `*.pcapng`, registration state, `.env` and Python caches.
- The code does not issue door-unlock, relay, actuator, firmware or settings-write commands.
- Tested on one U1000 Pro firmware. The default advertised `PushVersion=3.0.1` is an intentional diagnostic compatibility value, **not** the reader's observed reported version.
- Device event timestamps may differ from the server clock; initialization may upload historical events.

## References

- ZKTeco, *Security PUSH Communication Protocol* (2020), protocol reference (not redistributed here).
- ZKTeco, *Attendance PUSH Communication Protocol* (March 2020), for comparison. Attendance `ATTLOG` is not the same as access-control `rtlog`.
- [ZKTeco PUSH SDK Stack Overflow discussion](https://stackoverflow.com/questions/65844119/zkteco-push-sdk) — `OK` applies to some acknowledgements, **not every registration stage**.

## Contributions

Open issues or pull requests describing your device **model, firmware version, protocol version, HTTP endpoints and redacted responses**. Do **not** share real RFID identifiers, device serials, registration/session codes, passwords, private personal information or raw packet captures.

## License

MIT. Independent community implementation; **not affiliated with or endorsed by ZKTeco**.
