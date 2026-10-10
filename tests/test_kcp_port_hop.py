import pathlib
import socket
import sys
import threading
import time
import types
import unittest
from socketserver import BaseRequestHandler, TCPServer, ThreadingMixIn

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'luci-app-ssr-plus/root/usr/bin'))
if sys.platform == 'win32':
    sys.modules['syslog'] = types.SimpleNamespace(LOG_NOTICE=5, openlog=lambda *_args: None,
                                                  syslog=lambda *_args: None)
try:
    import kcp_port_hop
except ImportError:
    kcp_port_hop = None


class EchoHandler(BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.server.prefix)
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


class ThreadedTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class FakeProcess:
    def __init__(self):
        self.terminated = False

    def terminate(self):
        self.terminated = True


class KcpPortHopTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(kcp_port_hop, 'KcpTun port-hop implementation is missing')

    def test_builds_remote_address_from_a_valid_port_range(self):
        self.assertEqual(kcp_port_hop.remote_address('kcp.example', '3000-3010'),
                         'kcp.example:3000-3010')

    def test_rejects_invalid_remote_port_ranges(self):
        for value in ('', '0-10', '4000-3999', '1-65536', '4000-5000-6000', 'abc'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    kcp_port_hop.remote_address('kcp.example', value)

    def test_empty_hop_interval_uses_six_hundred_seconds(self):
        self.assertEqual(kcp_port_hop.hop_interval(''), 600)

    def test_custom_hop_interval_is_used_and_out_of_range_values_are_rejected(self):
        self.assertEqual(kcp_port_hop.hop_interval('90'), 90)
        for value in ('0', '86401', 'five'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    kcp_port_hop.hop_interval(value)

    def test_client_uses_port_range_and_generation_specific_local_listener(self):
        self.assertEqual(
            kcp_port_hop.client_command('/usr/bin/kcptun-client',
                                        'kcp.example:3000-3010', 43127,
                                        'secret', '--nocomp'),
            ['/usr/bin/kcptun-client', '-r', 'kcp.example:3000-3010',
             '-l', '127.0.0.1:43127', '--key', 'secret', '--nocomp'])

    def test_existing_sessions_drain_on_old_backend_after_new_connections_switch(self):
        old_server = ThreadedTCPServer(('127.0.0.1', 0), EchoHandler)
        old_server.prefix = b'old'
        new_server = ThreadedTCPServer(('127.0.0.1', 0), EchoHandler)
        new_server.prefix = b'new'
        threading.Thread(target=old_server.serve_forever, daemon=True).start()
        threading.Thread(target=new_server.serve_forever, daemon=True).start()
        old_process = FakeProcess()
        proxy = kcp_port_hop.PortHopProxy('127.0.0.1', 0)
        old_client = None
        new_client = None
        try:
            proxy.start()
            proxy.set_backend('127.0.0.1', old_server.server_address[1], old_process)
            old_client = socket.create_connection(proxy.address, timeout=2)
            self.assertEqual(old_client.recv(3), b'old')

            proxy.set_backend('127.0.0.1', new_server.server_address[1], FakeProcess())
            self.assertFalse(old_process.terminated)
            old_client.sendall(b'live')
            self.assertEqual(old_client.recv(4), b'live')

            new_client = socket.create_connection(proxy.address, timeout=2)
            self.assertEqual(new_client.recv(3), b'new')
            new_client.sendall(b'new-flow')
            self.assertEqual(new_client.recv(8), b'new-flow')

            old_client.close()
            old_client = None
            deadline = time.time() + 2
            while not old_process.terminated and time.time() < deadline:
                time.sleep(0.01)
            self.assertTrue(old_process.terminated)
        finally:
            if old_client:
                old_client.close()
            if new_client:
                new_client.close()
            proxy.close()
            old_server.shutdown()
            old_server.server_close()
            new_server.shutdown()
            new_server.server_close()


if __name__ == '__main__':
    unittest.main()
