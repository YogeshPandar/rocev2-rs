"""Exercise the C peer's control codec without opening an RDMA device."""
import pathlib
import struct
import subprocess
import unittest

PEER = pathlib.Path(__file__).resolve().parents[1] / 'rxe-peer' / 'rxe-peer'
FORMAT = '>4sHH4s6sHIIIQQ6BH8s'


class ProtocolTests(unittest.TestCase):
    @unittest.skipUnless(PEER.is_file(), 'build the reference peer first')
    def test_c_golden_record_matches_network_order_layout(self):
        result = subprocess.run([str(PEER), '--self-test'], check=True, text=True,
                                capture_output=True, timeout=5)
        actual = bytes.fromhex(result.stdout.strip())
        expected = struct.pack(FORMAT, b'RCV2', 1, 64, bytes([192, 0, 2, 1]), bytes(6),
                               1024, 2, 0xfffff0, 0x12345678, 0x0102030405060708,
                               4096, 6, 7, 14, 1, 1, 1, 49152, bytes(8))
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 64)

    @unittest.skipUnless(PEER.is_file(), 'build the reference peer first')
    def test_invalid_arguments_fail_before_device_access(self):
        args = ['unused', '192.0.2.1', '18515', '1', '0', '0', '1024', '0xfffff0', '1']
        for index, value in [(5, '-1'), (6, '129'), (7, '16777216'), (8, '0'), (4, '2')]:
            command = args.copy()
            command[index] = value
            result = subprocess.run([str(PEER), *command], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr.decode())


if __name__ == '__main__':
    unittest.main()
