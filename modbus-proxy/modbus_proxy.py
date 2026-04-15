#!/usr/bin/env python3
"""
Modbus TCP proxy — sits in front of Conpot on port 502.

Intercepts FC43/MEI=0x0E (Read Device Identification) and synthesizes a
proper Siemens S7-200 response. Without this, Conpot returns b'' because it
treats unit_id=0 as a broadcast address and FC43 is not in its broadcastable
list — a clear honeypot fingerprint. All other function codes are forwarded
to Conpot unchanged.
"""
import asyncio
import json
import os
import struct
from datetime import datetime, timezone

CONPOT_HOST = os.environ.get("CONPOT_HOST", "conpot")
CONPOT_PORT = int(os.environ.get("CONPOT_PORT", 5020))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", 502))

# Modbus spec max PDU = 253 bytes (RS-485 heritage); 260 is a generous ceiling.
# A larger MBAP length field means a malformed or crafted packet — reject it so
# an attacker cannot make the proxy allocate 64 KB per connection.
_MAX_PDU_BYTES = 260

# Must match <device_info> in conpot/templates/default/modbus.xml
VENDOR_NAME = b"Siemens"
PRODUCT_CODE = b"SIMATIC"
REVISION = b"S7-200"


def log(event: dict):
    print(json.dumps(event), flush=True)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_fc43_response(transaction_id: bytes, unit_id: int, read_dev_id_code: int) -> bytes:
    """
    FC43 / MEI 0x0E Read Device Identification response.
    Conformity level 0x01 = basic stream only (objects 0x00–0x02).
    read_dev_id_code is echoed back from the request per the Modbus spec.
    """
    objs = b""
    for obj_id, val in [(0x00, VENDOR_NAME), (0x01, PRODUCT_CODE), (0x02, REVISION)]:
        objs += bytes([obj_id, len(val)]) + val
    # PDU: FC=0x2B | MEI=0x0E | ReadDevIdCode | ConformityLevel | MoreFollow | NextObjId | NumObjects | objects
    pdu = bytes([0x2B, 0x0E, read_dev_id_code, 0x01, 0x00, 0x00, 3]) + objs
    mbap = transaction_id + b"\x00\x00" + struct.pack(">H", 1 + len(pdu)) + bytes([unit_id])
    return mbap + pdu


async def _read_mbap_pdu(reader: asyncio.StreamReader):
    """Read one Modbus TCP frame: 7-byte MBAP header + PDU. Returns (header, pdu)."""
    header = await reader.readexactly(7)
    length = struct.unpack(">H", header[4:6])[0]
    pdu_len = length - 1  # MBAP length includes unit_id byte
    if pdu_len < 0 or pdu_len > _MAX_PDU_BYTES:
        raise ValueError(f"oversized_pdu length={length}")
    pdu = await reader.readexactly(pdu_len)
    return header, pdu


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "unknown"
    src_port = peer[1] if peer else 0

    log({"timestamp": _now(), "event": "modbus_connect", "src_ip": src_ip, "src_port": src_port})

    try:
        backend_reader, backend_writer = await asyncio.open_connection(CONPOT_HOST, CONPOT_PORT)
    except Exception as exc:
        log({"timestamp": _now(), "event": "backend_connect_failed", "error": str(exc)})
        writer.close()
        return

    async def client_to_backend():
        try:
            while True:
                header, pdu = await _read_mbap_pdu(reader)
                txn_id = header[0:2]
                unit_id = header[6]
                fc = pdu[0] if pdu else None

                if fc == 0x2B and len(pdu) >= 2 and pdu[1] == 0x0E:
                    read_dev_id_code = pdu[2] if len(pdu) > 2 else 0x01
                    log({
                        "timestamp": _now(),
                        "event": "modbus_fc43_intercepted",
                        "src_ip": src_ip,
                        "unit_id": unit_id,
                        "read_dev_id_code": read_dev_id_code,
                        "object_id": pdu[3] if len(pdu) > 3 else 0,
                        "raw_request": (header + pdu).hex(),
                        "vendor": VENDOR_NAME.decode(),
                        "product": PRODUCT_CODE.decode(),
                        "revision": REVISION.decode(),
                    })
                    writer.write(_build_fc43_response(txn_id, unit_id, read_dev_id_code))
                    await writer.drain()
                else:
                    if fc is not None:
                        log({
                            "timestamp": _now(),
                            "event": "modbus_request",
                            "src_ip": src_ip,
                            "unit_id": unit_id,
                            "function_code": fc,
                            "raw": (header + pdu).hex(),
                        })
                    backend_writer.write(header + pdu)
                    await backend_writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        except ValueError as exc:
            log({"timestamp": _now(), "event": "modbus_protocol_error",
                 "src_ip": src_ip, "error": str(exc)})

    async def backend_to_client():
        try:
            while True:
                header, pdu = await _read_mbap_pdu(backend_reader)
                writer.write(header + pdu)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        except ValueError as exc:
            log({"timestamp": _now(), "event": "modbus_protocol_error",
                 "src_ip": src_ip, "error": str(exc)})

    t1 = asyncio.create_task(client_to_backend())
    t2 = asyncio.create_task(backend_to_client())
    _done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass

    log({"timestamp": _now(), "event": "modbus_disconnect", "src_ip": src_ip})
    for conn in (backend_writer, writer):
        try:
            conn.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", LISTEN_PORT)
    log({
        "timestamp": _now(),
        "event": "modbus_proxy_started",
        "listen_port": LISTEN_PORT,
        "backend": f"{CONPOT_HOST}:{CONPOT_PORT}",
    })
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
