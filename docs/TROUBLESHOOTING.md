# Troubleshooting Security PUSH

## Device continuously registers

Look for `POST /iclock/registry` followed by `GET /iclock/push`. If the latter returns 404, registration never completes. The receiver supports `/iclock/push` and responds with a configuration block.

## Only `GET /iclock/cdata` appears

Confirm the device's configured server IP/port, supported PUSH mode, response body for `options=all` and whether registration is needed. An HTTP `200 OK` alone does not guarantee the device received an initialization configuration.

## No `cardno` events

Look for `POST /iclock/cdata?...&table=rtlog`. `rtstate` reports controller status, not RFID events. Attendance `ATTLOG` may carry only a person PIN; it is different from Security PUSH `rtlog`. Scan a known tag and a different unknown tag separately.

## Common error: port already used

`sudo ss -lntp | grep ':6000'` then pick a free port. The existing gateway can continue on a different port.

## Capture safely

`sudo tcpdump -i any -nn -s0 -A 'host DEVICE_IP and tcp port 6000'`

Captures and journals contain sensitive information. Store securely and redact before sharing.

## Firmware support

The tested device identified itself as `DeviceType=acc`, model U1000 Pro with `IsOnlyRFMachine=1`. Some attendance devices use a different protocol sequence; choose `--mode attendance` only if appropriate.
