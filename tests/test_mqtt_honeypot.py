import asyncio
import importlib.util
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MQTT_PATH = ROOT / "mqtt" / "mqtt_honeypot.py"


def load_mqtt_module():
    spec = importlib.util.spec_from_file_location("mqtt_honeypot", MQTT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mqtt_string(value):
    encoded = value.encode("utf-8")
    return struct.pack(">H", len(encoded)) + encoded


def encode_remaining_length(value):
    encoded = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value > 0:
            byte |= 0x80
        encoded.append(byte)
        if value == 0:
            return bytes(encoded)


async def read_packet_from(data, module):
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return await module.read_packet(reader)


class MQTTHoneypotTests(unittest.TestCase):
    def setUp(self):
        self.module = load_mqtt_module()

    def test_read_packet_and_parse_connect_accepts_normal_connect(self):
        # flags=0xc2: username(0x80)|password(0x40)|clean_session(0x02)
        # keep_alive=0x003c (60 seconds), protocol level 4 = MQTT 3.1.1
        payload = (
            mqtt_string("MQTT")
            + b"\x04"
            + b"\xc2"
            + b"\x00\x3c"
            + mqtt_string("client")
            + mqtt_string("user")
            + mqtt_string("pass")
        )
        packet = b"\x10" + encode_remaining_length(len(payload)) + payload

        packet_type, raw_packet, parsed_payload = asyncio.run(read_packet_from(packet, self.module))
        result = self.module.parse_connect(parsed_payload)

        self.assertEqual(packet_type, self.module.MQTT_CONNECT)
        self.assertEqual(raw_packet, packet)
        self.assertEqual(result["client_id"], "client")
        self.assertEqual(result["username"], "user")
        self.assertEqual(result["password"], "pass")
        self.assertEqual(result["mqtt_version"], "3.1.1")
        self.assertEqual(result["keep_alive"], 60)
        self.assertTrue(result["clean_session"])
        self.assertFalse(result["will_flag"])

    def test_parse_connect_with_will(self):
        # flags=0xee: username(0x80)|password(0x40)|will_retain(0x20)|will_qos_lsb(0x08)|will(0x04)|clean_session(0x02)
        # 0x80|0x40|0x20|0x08|0x04|0x02 = 0xee
        will_payload = b"\x00\x04dead"
        payload = (
            mqtt_string("MQTT")
            + b"\x04"
            + b"\xee"
            + b"\x00\x1e"
            + mqtt_string("client2")
            + mqtt_string("alerts/node1")
            + will_payload
            + mqtt_string("admin")
            + mqtt_string("secret")
        )
        result = self.module.parse_connect(payload)

        self.assertTrue(result["will_flag"])
        self.assertEqual(result["will_topic"], "alerts/node1")
        self.assertEqual(result["will_payload_len"], 4)
        self.assertEqual(result["will_qos"], 1)
        self.assertTrue(result["will_retain"])

    def test_parse_connect_returns_empty_dict_on_corrupt_payload(self):
        result = self.module.parse_connect(b"\x00\x04")
        self.assertEqual(result, {})

    def test_read_packet_rejects_oversized_packet(self):
        packet = b"\x10" + encode_remaining_length(self.module.MAX_PACKET_BYTES + 1)

        with self.assertRaisesRegex(self.module.MQTTPacketError, "packet_too_large"):
            asyncio.run(read_packet_from(packet, self.module))

    def test_read_packet_rejects_malformed_remaining_length(self):
        packet = b"\x10\x80\x80\x80\x80"

        with self.assertRaisesRegex(self.module.MQTTPacketError, "malformed_remaining_length"):
            asyncio.run(read_packet_from(packet, self.module))


if __name__ == "__main__":
    unittest.main()
