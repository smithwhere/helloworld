import importlib.util
import pathlib
import socket
import struct
import sys
import types
import unittest

# Windows cannot import the Linux syslog module. None of these tests logs or
# closes a system socket; production parsing and connection selection stay real.
if sys.platform == 'win32':
    sys.modules['syslog'] = types.SimpleNamespace()
ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'luci-app-ssr-plus/root/usr/bin/google-idle-guard.py'

def hello(host='www.google.com', protocols=(b'h2',), padding=0):
    name = host.encode()
    sni = b'\0' + len(name).to_bytes(2, 'big') + name
    sni = len(sni).to_bytes(2, 'big') + sni
    alpn = b''.join(bytes([len(p)]) + p for p in protocols)
    alpn = len(alpn).to_bytes(2, 'big') + alpn
    ext = b'\0\0' + len(sni).to_bytes(2, 'big') + sni
    ext += b'\0\x10' + len(alpn).to_bytes(2, 'big') + alpn
    ext += b'\0\x15' + padding.to_bytes(2, 'big') + bytes(padding)
    body = b'\x03\x03' + bytes(32) + b'\0\0\x02\x13\x01\x01\0'
    body += len(ext).to_bytes(2, 'big') + ext
    hs = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + len(hs).to_bytes(2, 'big') + hs

def packet(client, port, seq, data, flags=0x18):
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into('!H', ip, 2, 40 + len(data))
    ip[9] = 6
    ip[12:16] = socket.inet_aton(client)
    ip[16:20] = socket.inet_aton('142.251.154.119')
    tcp = bytearray(20)
    struct.pack_into('!HHI', tcp, 0, port, 443, seq)
    tcp[12:14] = bytes([0x50, flags])
    return bytes(12) + b'\x08\x00' + ip + tcp + data

class GuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SCRIPT.exists():
            return
        spec = importlib.util.spec_from_file_location('guard', SCRIPT)
        cls.guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.guard)

    def setUp(self):
        self.assertTrue(SCRIPT.exists(), 'SSR Plus has no Google idle recovery implementation')
        self.g = self.guard

    def test_separates_devices_with_identical_destination_and_source_port(self):
        t = self.g.FlowTracker(['google.com'])
        t.feed(packet('192.168.1.2', 50000, 1, hello()), 0)
        t.feed(packet('192.168.1.3', 50000, 1, hello('example.com')), 0)
        self.assertEqual(list(t.tracked), [('192.168.1.2', 50000, '142.251.154.119', 443)])

    def test_large_fragmented_clienthello_with_retransmission(self):
        t = self.g.FlowTracker(['google.com'])
        data = hello(padding=9000)
        parts = [(1, data[:1000]), (2001, data[2000:]), (1, data[:1000]), (1001, data[1000:2000])]
        for seq, payload in parts:
            t.feed(packet('192.168.1.2', 50000, seq, payload), 0)
        self.assertEqual(list(t.tracked.values())[0][0], 'www.google.com')

    def test_requires_h2_and_exact_domain_suffix(self):
        for host, alpn in [('google.com.evil.test', (b'h2',)), ('notgoogle.com', (b'h2',)),
                           ('www.google.com', (b'http/1.1',))]:
            t = self.g.FlowTracker(['google.com'])
            t.feed(packet('192.168.1.2', 50000, 1, hello(host, alpn)), 0)
            self.assertFalse(t.tracked)

    def test_syn_removes_previous_classification(self):
        t = self.g.FlowTracker(['google.com'])
        t.feed(packet('192.168.1.2', 50000, 1, hello()), 0)
        t.feed(packet('192.168.1.2', 50000, 1000, b'', flags=2), 1)
        self.assertFalse(t.tracked)

    def test_expiry_requires_idle_empty_queues_and_current_nat(self):
        key = ('192.168.1.2', 50000, '142.251.154.119', 443)
        record = dict(client_ip=key[0], client_port=key[1], local_ip='192.168.1.1',
                      local_port=1234, idle_ms=8100, queues=(0, 0), inode=77)
        mapping = {(key[0], key[1], '192.168.1.1', 1234): key}
        tracked = {key: ('www.google.com', 0)}
        self.assertEqual(self.g.expiry_key(record, mapping, tracked, 8), key)
        for updates in [dict(idle_ms=7999), dict(queues=(1, 0)), dict(queues=(0, 1)), dict(idle_ms=None)]:
            self.assertIsNone(self.g.expiry_key(dict(record, **updates), mapping, tracked, 8))
        self.assertIsNone(self.g.expiry_key(record, {}, tracked, 8))

    def test_nat_does_not_merge_same_port_on_two_clients(self):
        lines = []
        for ip in ('192.168.1.2', '192.168.1.3'):
            lines.append('ipv4 2 tcp 6 600 ESTABLISHED src=%s dst=142.251.154.119 sport=50000 dport=443 '
                         'src=192.168.1.1 dst=%s sport=1234 dport=50000 [ASSURED]' % (ip, ip))
        result = self.g.parse_nat(lines, '*')
        self.assertEqual(len(result), 2)
        self.assertEqual(result[('192.168.1.3', 50000, '192.168.1.1', 1234)],
                         ('192.168.1.3', 50000, '142.251.154.119', 443))

if __name__ == '__main__':
    unittest.main()
