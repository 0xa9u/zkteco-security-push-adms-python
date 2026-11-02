# Contributing

Thanks for helping improve this independent ZKTeco Security PUSH / ADMS diagnostic receiver.

## Before opening an issue
Include the device model, firmware and protocol version, a concise sequence of HTTP endpoints, expected behaviour and actual behaviour. **Redact** device serial numbers, RFID cards, enrolled PINs, user identities, session/registry codes, LAN addressing and all authentication material.

## Local checks

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile zkteco_push_probe.py
```

## Pull requests
- Keep new dependencies optional; the receiver currently relies on the Python standard library.
- Add or update a test for protocol changes.
- Preserve raw-event journal-before-acknowledgement behaviour.
- Document firmware-specific compatibility rather than claiming universal support.
- Do not silently add unlock commands, barrier control, or configuration writes.
- Use entirely synthetic request captures and identifiers.

This is a diagnostic prototype. Changes that could influence physical access require explicit safety review and separate production hardening.
