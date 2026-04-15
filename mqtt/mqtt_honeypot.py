#!/usr/bin/env python3
"""
MQTT credential-capturing proxy for honeypot use.
Listens on port 1883, intercepts CONNECT packets to log client_id/username/password,
then proxies the connection transparently to the real broker.
Attackers see a normal MQTT broker; we see their credentials.
No external dependencies — pure stdlib asyncio.
"""

import asyncio
import json
import os
import struct
from datetime import datetime, timezone

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", 1883))
BROKER_HOST = os.environ.get("BROKER_HOST", "mosquitto")
BROKER_PORT = int(os.environ.get("BROKER_PORT", 1883))
MAX_PACKET_BYTES = int(os.environ.get("MAX_PACKET_BYTES", 1024 * 1024))
FIRST_PACKET_TIMEOUT = int(os.environ.get("FIRST_PACKET_TIMEOUT", 10))

MQTT_CONNECT = 1


class MQTTPacketError(Exception):
    """Raised when the first MQTT packet is malformed or unsafe to proxy."""


def log(event: dict):
    print(json.dumps(event), flush=True)


async def read_packet(reader: asyncio.StreamReader):
    """Read one complete MQTT packet. Returns (packet_type, raw_bytes, payload_bytes)."""
    header = await reader.readexactly(1)
    packet_type = (header[0] >> 4) & 0x0F

    # MQTT variable-length remaining length field (up to 4 bytes)
    remaining = 0
    multiplier = 1
    length_bytes = b""
    for index in range(4):
        byte = await reader.readexactly(1)
        length_bytes += byte
        remaining += (byte[0] & 0x7F) * multiplier
        multiplier *= 128
        if not (byte[0] & 0x80):
            break
        if index == 3:
            raise MQTTPacketError("malformed_remaining_length")

    if remaining > MAX_PACKET_BYTES:
        raise MQTTPacketError("packet_too_large")

    payload = await reader.readexactly(remaining) if remaining > 0 else b""
    return packet_type, header + length_bytes + payload, payload


def parse_mqtt_string(data: bytes, pos: int):
    """Parse a 2-byte length-prefixed UTF-8 string from data at pos."""
    if pos + 2 > len(data):
        return None, pos
    length = struct.unpack(">H", data[pos:pos + 2])[0]
    pos += 2
    if pos + length > len(data):
        return None, pos
    return data[pos:pos + length].decode("utf-8", errors="replace"), pos + length


_MQTT_VERSIONS = {3: "3.1", 4: "3.1.1", 5: "5.0"}


def parse_connect(payload: bytes) -> dict:
    """Extract all relevant fields from a MQTT CONNECT payload."""
    try:
        pos = 0
        proto_name, pos = parse_mqtt_string(payload, pos)
        proto_level = payload[pos]
        pos += 1

        flags = payload[pos]
        pos += 1

        keep_alive = struct.unpack(">H", payload[pos:pos + 2])[0]
        pos += 2

        clean_session = bool(flags & 0x02)
        has_will = bool(flags & 0x04)
        will_qos = (flags >> 3) & 0x03
        will_retain = bool(flags & 0x20)
        has_username = bool(flags & 0x80)
        has_password = bool(flags & 0x40)

        client_id, pos = parse_mqtt_string(payload, pos)

        will_topic = None
        will_payload_len = None
        if has_will:
            will_topic, pos = parse_mqtt_string(payload, pos)
            if pos + 2 <= len(payload):
                will_payload_len = struct.unpack(">H", payload[pos:pos + 2])[0]
                pos += 2 + will_payload_len

        username = None
        if has_username:
            username, pos = parse_mqtt_string(payload, pos)

        password = None
        if has_password and pos + 2 <= len(payload):
            pwd_len = struct.unpack(">H", payload[pos:pos + 2])[0]
            pos += 2
            password = payload[pos:pos + pwd_len].decode("utf-8", errors="replace")

        return {
            "client_id":        client_id,
            "username":         username,
            "password":         password,
            "mqtt_version":     _MQTT_VERSIONS.get(proto_level, f"unknown({proto_level})"),
            "proto_name":       proto_name,
            "keep_alive":       keep_alive,
            "clean_session":    clean_session,
            "will_flag":        has_will,
            "will_qos":         will_qos if has_will else None,
            "will_retain":      will_retain if has_will else None,
            "will_topic":       will_topic,
            "will_payload_len": will_payload_len,
        }
    except Exception:
        return {}


async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
    """Forward bytes from src to dst until EOF or error."""
    try:
        while True:
            data = await src.read(4096)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    peer = client_writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "unknown"
    src_port = peer[1] if peer else 0
    broker_writer = None

    try:
        # First packet from any MQTT client must be CONNECT
        packet_type, raw_packet, payload = await asyncio.wait_for(
            read_packet(client_reader), timeout=FIRST_PACKET_TIMEOUT
        )

        if packet_type == MQTT_CONNECT:
            connect_data = parse_connect(payload)
            log({
                "timestamp":    datetime.now(timezone.utc).isoformat(),
                "event":        "mqtt_connect_attempt",
                "src_ip":       src_ip,
                "src_port":     src_port,
                "payload_size": len(payload),
                **connect_data,
            })
        else:
            log({
                "timestamp":   datetime.now(timezone.utc).isoformat(),
                "event":       "mqtt_unexpected_packet",
                "src_ip":      src_ip,
                "packet_type": packet_type,
            })

        # Proxy the connection to the real broker transparently
        broker_reader, broker_writer = await asyncio.open_connection(BROKER_HOST, BROKER_PORT)
        broker_writer.write(raw_packet)
        await broker_writer.drain()

        # Bidirectional forwarding
        await asyncio.gather(
            pipe(client_reader, broker_writer),
            pipe(broker_reader, client_writer),
        )

    except asyncio.TimeoutError:
        pass   # Scanner opened TCP but never sent CONNECT
    except asyncio.IncompleteReadError:
        pass   # Client disconnected mid-handshake
    except MQTTPacketError as e:
        reason = str(e)
        log({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event":     "mqtt_packet_too_large" if reason == "packet_too_large" else "mqtt_malformed_packet",
            "src_ip":    src_ip,
            "src_port":  src_port,
            "reason":    reason,
        })
    except ConnectionRefusedError:
        log({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event":     "broker_unreachable",
            "src_ip":    src_ip,
        })
    except Exception as e:
        log({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event":     "error",
            "src_ip":    src_ip,
            "error":     str(e),
        })
    finally:
        try:
            client_writer.close()
        except Exception:
            pass
        if broker_writer:
            try:
                broker_writer.close()
            except Exception:
                pass


async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT)
    log({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event":     "honeypot_started",
        "listen":    f"{LISTEN_HOST}:{LISTEN_PORT}",
        "broker":    f"{BROKER_HOST}:{BROKER_PORT}",
    })
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
