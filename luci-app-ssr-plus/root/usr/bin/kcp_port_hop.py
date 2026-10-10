#!/usr/bin/python3
"""Rotate Kcptun backends without moving established TCP sessions."""
import argparse
import os
import select
import shlex
import signal
import socket
import subprocess
import syslog
import threading
import time


def remote_address(server, ports):
    server = (server or '').strip()
    ports = (ports or '').strip()
    if not server:
        raise ValueError('KcpTun server address is empty')
    pieces = ports.split('-')
    if len(pieces) > 2 or any(not item.isdigit() for item in pieces):
        raise ValueError('KcpTun port must be a port or a min-max range')
    numbers = [int(item) for item in pieces]
    if any(number < 1 or number > 65535 for number in numbers):
        raise ValueError('KcpTun ports must be between 1 and 65535')
    if len(numbers) == 2 and numbers[0] > numbers[1]:
        raise ValueError('KcpTun port range start must not exceed end')
    if ':' in server and not server.startswith('['):
        server = '[' + server + ']'
    return server + ':' + ports


def hop_interval(value):
    if value is None or str(value).strip() == '':
        return 600
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        raise ValueError('KcpTun hop interval must be an integer')
    if seconds < 1 or seconds > 86400:
        raise ValueError('KcpTun hop interval must be between 1 and 86400 seconds')
    return seconds


def client_command(binary, remote, local_port, password='', params=''):
    command = [binary, '-r', remote, '-l', '127.0.0.1:%d' % local_port]
    if password:
        command.extend(['--key', password])
    command.extend(shlex.split(params or ''))
    return command


class BackendGeneration:
    def __init__(self, host, port, process=None):
        self.host = host
        self.port = int(port)
        self.process = process
        self.active_sessions = 0
        self.retired = False
        self.stopped = False


class PortHopProxy:
    """A stable local listener that pins each accepted stream to one backend."""
    def __init__(self, host, port, connect_timeout=10):
        self.host = host
        self.port = int(port)
        self.connect_timeout = connect_timeout
        self.listener = None
        self.accept_thread = None
        self.lock = threading.RLock()
        self.active_backend = None
        self.generations = []
        self.connections = set()
        self.stopping = threading.Event()

    @property
    def address(self):
        if self.listener is None:
            return self.host, self.port
        return self.listener.getsockname()[:2]

    def start(self):
        if self.listener is not None:
            return
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen(256)
        listener.settimeout(0.25)
        self.listener = listener
        self.port = listener.getsockname()[1]
        self.accept_thread = threading.Thread(target=self._accept_loop,
                                              name='kcp-port-hop-listener', daemon=True)
        self.accept_thread.start()

    def set_backend(self, host, port, process=None):
        new = BackendGeneration(host, port, process)
        stop_process = None
        with self.lock:
            old = self.active_backend
            self.generations.append(new)
            self.active_backend = new
            if old is not None:
                old.retired = True
                stop_process = self._mark_drained(old)
        self._stop_process(stop_process)
        return new

    def _accept_loop(self):
        while not self.stopping.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                generation = self.active_backend
                if generation is None or self.stopping.is_set():
                    client.close()
                    continue
                generation.active_sessions += 1
                self.connections.add(client)
            threading.Thread(target=self._proxy_session, args=(client, generation),
                             name='kcp-port-hop-session', daemon=True).start()

    def _proxy_session(self, client, generation):
        upstream = None
        try:
            upstream = socket.create_connection((generation.host, generation.port),
                                                self.connect_timeout)
            client.setblocking(False)
            upstream.setblocking(False)
            open_read = {client: True, upstream: True}
            peer = {client: upstream, upstream: client}
            while any(open_read.values()) and not self.stopping.is_set():
                readable, _, _ = select.select(
                    [sock for sock, is_open in open_read.items() if is_open], [], [], 0.5)
                for source in readable:
                    try:
                        data = source.recv(65536)
                    except OSError:
                        data = b''
                    if not data:
                        open_read[source] = False
                        try:
                            peer[source].shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    destination = peer[source]
                    view = memoryview(data)
                    while view:
                        try:
                            sent = destination.send(view)
                        except (BlockingIOError, InterruptedError):
                            _, writable, _ = select.select([], [destination], [], 1)
                            if not writable:
                                continue
                            continue
                        if sent <= 0:
                            raise OSError('KcpTun backend closed while forwarding')
                        view = view[sent:]
        except OSError:
            pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            with self.lock:
                self.connections.discard(client)
                generation.active_sessions = max(0, generation.active_sessions - 1)
                stop_process = self._mark_drained(generation)
            self._stop_process(stop_process)

    def _mark_drained(self, generation):
        if not generation.retired or generation.active_sessions or generation.stopped:
            return None
        generation.stopped = True
        process = generation.process
        if process is None:
            try:
                self.generations.remove(generation)
            except ValueError:
                pass
            return None
        try:
            self.generations.remove(generation)
        except ValueError:
            pass
        return process

    @staticmethod
    def _stop_process(process):
        if process is None:
            return
        try:
            if process.poll() is None:
                process.terminate()
        except AttributeError:
            process.terminate()
        try:
            process.wait(timeout=5)
        except (AttributeError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except AttributeError:
                pass

    def close(self):
        self.stopping.set()
        if self.listener is not None:
            try:
                self.listener.close()
            except OSError:
                pass
        to_stop = []
        with self.lock:
            for client in list(self.connections):
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    client.close()
                except OSError:
                    pass
            for generation in list(self.generations):
                generation.retired = True
                generation.active_sessions = 0
                process = self._mark_drained(generation)
                if process is not None:
                    to_stop.append(process)
        for process in to_stop:
            self._stop_process(process)
        if self.accept_thread is not None:
            self.accept_thread.join(timeout=2)


def allocate_local_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def start_generation(binary, remote, password, params, timeout=30):
    local_port = allocate_local_port()
    command = client_command(binary, remote, local_port, password, params)
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               close_fds=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError('kcptun-client exited before its local listener was ready')
        try:
            with socket.create_connection(('127.0.0.1', local_port), timeout=1):
                return local_port, process
        except OSError:
            time.sleep(0.1)
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
    raise RuntimeError('kcptun-client local listener did not become ready')


def emit(event, **fields):
    message = 'kcp-port-hop: %s %s' % (event, ' '.join(
        '%s=%s' % item for item in sorted(fields.items())))
    print(message, flush=True)
    try:
        syslog.syslog(syslog.LOG_NOTICE, message)
    except Exception:
        pass


def run(args):
    remote = remote_address(args.server, args.remote_ports)
    interval = hop_interval(args.interval)
    proxy = PortHopProxy('127.0.0.1', args.listen_port)
    stop_event = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda _sig, _frame: stop_event.set())
    syslog.openlog('kcp-port-hop')
    process = None
    try:
        port, process = start_generation(args.binary, remote, args.password, args.params)
        proxy.start()
        proxy.set_backend('127.0.0.1', port, process)
        emit('started', listen=proxy.address[1], remote=remote, interval=interval)
        next_hop = time.monotonic() + interval
        while not stop_event.is_set():
            active = proxy.active_backend
            if active is not None and active.process.poll() is not None:
                emit('backend_exited', port=active.port)
                next_hop = time.monotonic()
            wait = max(0, min(1, next_hop - time.monotonic()))
            stop_event.wait(wait)
            if stop_event.is_set() or time.monotonic() < next_hop:
                continue
            new_process = None
            try:
                port, new_process = start_generation(args.binary, remote,
                                                     args.password, args.params)
                proxy.set_backend('127.0.0.1', port, new_process)
                emit('rotated', listen=proxy.address[1], backend=port, remote=remote)
                next_hop = time.monotonic() + interval
            except (OSError, RuntimeError) as error:
                if new_process is not None and new_process.poll() is None:
                    new_process.terminate()
                emit('rotation_failed', error=str(error))
                next_hop = time.monotonic() + min(interval, 30)
    finally:
        proxy.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True)
    parser.add_argument('--remote-ports', required=True)
    parser.add_argument('--listen-port', required=True, type=int)
    parser.add_argument('--interval', default='600')
    parser.add_argument('--password', default='')
    parser.add_argument('--params', default='')
    parser.add_argument('--binary', default='/usr/bin/kcptun-client')
    run(parser.parse_args())


if __name__ == '__main__':
    main()
