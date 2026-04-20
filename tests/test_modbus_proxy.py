import asyncio
import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROXY_PATH = ROOT / "modbus-proxy" / "modbus_proxy.py"


def load_proxy_module():
    spec = importlib.util.spec_from_file_location("modbus_proxy", PROXY_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ModbusProxyTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_proxy_module()

    def _parse_fc43_response(self, data: bytes) -> dict:
        """Parse an FC43/MEI=0x0E response into a dict for assertion."""
        # MBAP: txn_id(2) + proto(2) + length(2) + unit_id(1) = 7 bytes
        txn_id = data[0:2]
        proto = data[2:4]
        length = struct.unpack(">H", data[4:6])[0]
        unit_id = data[6]
        pdu = data[7:]
        self.assertEqual(proto, b"\x00\x00", "protocol ID must be 0 for Modbus TCP")
        self.assertEqual(length, 1 + len(pdu), "MBAP length field mismatch")
        # PDU: FC | MEI | ReadDevIdCode | ConformityLevel | MoreFollow | NextObjId | NumObjects
        fc = pdu[0]
        mei = pdu[1]
        read_dev_id_code = pdu[2]
        conformity = pdu[3]
        more_follow = pdu[4]
        next_obj_id = pdu[5]
        num_objects = pdu[6]
        objects = {}
        offset = 7
        for _ in range(num_objects):
            obj_id = pdu[offset]
            obj_len = pdu[offset + 1]
            obj_val = pdu[offset + 2: offset + 2 + obj_len].decode("ascii")
            objects[obj_id] = obj_val
            offset += 2 + obj_len
        return {
            "txn_id": txn_id, "unit_id": unit_id,
            "fc": fc, "mei": mei,
            "read_dev_id_code": read_dev_id_code,
            "conformity": conformity,
            "more_follow": more_follow,
            "next_obj_id": next_obj_id,
            "num_objects": num_objects,
            "objects": objects,
        }

    def _make_mbap(self, pdu: bytes, unit_id: int = 0, txn_id: bytes = b"\x00\x01") -> bytes:
        length = 1 + len(pdu)
        return txn_id + b"\x00\x00" + struct.pack(">H", length) + bytes([unit_id]) + pdu

    async def _read_from(self, data: bytes):
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        return await self.mod._read_mbap_pdu(reader)

    def test_fc43_response_structure(self):
        txn_id = b"\x5a\x47"
        response = self.mod._build_fc43_response(txn_id, unit_id=0, read_dev_id_code=0x01)
        parsed = self._parse_fc43_response(response)

        self.assertEqual(parsed["txn_id"], txn_id)
        self.assertEqual(parsed["unit_id"], 0)
        self.assertEqual(parsed["fc"], 0x2B)
        self.assertEqual(parsed["mei"], 0x0E)
        self.assertEqual(parsed["more_follow"], 0x00)
        self.assertEqual(parsed["num_objects"], 3)

    def test_fc43_response_device_identity(self):
        response = self.mod._build_fc43_response(b"\x00\x01", unit_id=1, read_dev_id_code=0x01)
        parsed = self._parse_fc43_response(response)

        self.assertEqual(parsed["objects"][0x00], "Siemens")
        self.assertEqual(parsed["objects"][0x01], "SIMATIC")
        self.assertEqual(parsed["objects"][0x02], "S7-200")

    def test_fc43_response_conformity_level(self):
        response = self.mod._build_fc43_response(b"\x00\x01", unit_id=1, read_dev_id_code=0x01)
        parsed = self._parse_fc43_response(response)
        # 0x01 = basic stream only (objects 0x00-0x02 supported)
        self.assertEqual(parsed["conformity"], 0x01)

    def test_fc43_response_unit_id_preserved(self):
        for uid in (0, 1, 255):
            response = self.mod._build_fc43_response(b"\x00\x01", unit_id=uid, read_dev_id_code=0x01)
            parsed = self._parse_fc43_response(response)
            self.assertEqual(parsed["unit_id"], uid, f"unit_id={uid} not preserved")

    def test_fc43_response_echoes_read_dev_id_code(self):
        for code in (0x01, 0x02, 0x04):
            response = self.mod._build_fc43_response(b"\x00\x01", unit_id=0, read_dev_id_code=code)
            parsed = self._parse_fc43_response(response)
            self.assertEqual(parsed["read_dev_id_code"], code, f"DevIdCode {code} not echoed")

    def test_read_mbap_pdu_rejects_oversized_length(self):
        # length field = 65535 (max uint16) → PDU would be 65534 bytes
        oversized_header = b"\x00\x01\x00\x00\xff\xff\x00"
        with self.assertRaises(ValueError, msg="oversized PDU should raise ValueError"):
            asyncio.run(self._read_from(oversized_header))

    def test_read_mbap_pdu_accepts_normal_packet(self):
        pdu = bytes([0x03, 0x00, 0x00, 0x00, 0x0A])  # FC3 Read Holding Registers
        frame = self._make_mbap(pdu)
        header, parsed_pdu = asyncio.run(self._read_from(frame))
        self.assertEqual(parsed_pdu, pdu)

    def test_read_mbap_pdu_rejects_zero_length(self):
        # length=0 means pdu_len = -1 → should raise
        bad_header = b"\x00\x01\x00\x00\x00\x00\x00"
        with self.assertRaises(ValueError):
            asyncio.run(self._read_from(bad_header))


if __name__ == "__main__":
    unittest.main()
