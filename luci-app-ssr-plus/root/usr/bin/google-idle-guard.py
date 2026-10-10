#!/usr/bin/python3
"""Recover Google h2 candidates with no recent SSR-to-client data.

Based on the N1 recovery service supplied with the diagnostic records.
No TLS decryption; each close requires current NAT and SSR socket ownership.
"""
import argparse, ctypes, glob, json, os, select, socket, struct, syslog, time


def duplicate_owned_socket(record, owner):
    """Duplicate exactly one SSR socket via pidfd, then verify its identity."""
    pid, fd = owner
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # Linux aarch64 syscall numbers (the replacement N1's architecture).
    pidfd = libc.syscall(ctypes.c_long(434), ctypes.c_int(pid), ctypes.c_uint(0))
    if pidfd < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    try:
        duplicate = libc.syscall(ctypes.c_long(438), ctypes.c_int(pidfd),
                                 ctypes.c_int(fd), ctypes.c_uint(0))
        if duplicate < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
    finally:
        os.close(pidfd)
    try:
        copied = socket.socket(fileno=duplicate)
    except Exception:
        os.close(duplicate)
        raise
    try:
        valid = (os.fstat(copied.fileno()).st_ino == record['inode'] and
                 copied.getsockname()[:2] == (record['local_ip'], record['local_port']) and
                 copied.getpeername()[:2] == (record['client_ip'], record['client_port']) and
                 copied.getsockopt(socket.SOL_SOCKET, 57, 8) == record['raw'][44:52])
        if valid:
            return copied
    except Exception:
        copied.close()
        raise
    copied.close()
    return None

def shutdown_owned_socket(record, owner, limit):
    copied = duplicate_owned_socket(record, owner)
    if copied is None:
        return False
    with copied:
        info = copied.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
        if len(info) < 56 or info[0] != 1:
            return False
        # This is the SSR redir's accepted client socket: last_data_sent is
        # traffic sent back to the client. Client requests/PINGs update
        # last_data_recv but must not hide an upstream that stopped replying.
        response_idle = struct.unpack_from('I', info, 44)[0]
        if response_idle < limit * 1000:
            return False
        libc = ctypes.CDLL(None, use_errno=True)
        for request in (0x541B, 0x5411):  # SIOCINQ and SIOCOUTQ.
            queued = ctypes.c_int()
            if libc.ioctl(copied.fileno(), request, ctypes.byref(queued)) < 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
            if queued.value:
                return False
        copied.shutdown(socket.SHUT_RDWR)
        return True

def emit(event, **fields):
    line=json.dumps(dict(event=event, **fields), sort_keys=True)
    print(line, flush=True)
    syslog.syslog(syslog.LOG_NOTICE, line)

def google_host(host, allowed):
    return any(host == suffix or host.endswith('.'+suffix) for suffix in allowed)

class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint32)]

class Program(ctypes.Structure):
    _fields_=[('length',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]

def messages(sock):
    while True:
        data=sock.recv(65536); p=0
        while p+16<=len(data):
            n,typ,flags,seq,pid=struct.unpack_from('IHHII',data,p)
            if n<16: raise RuntimeError('invalid netlink response')
            body=data[p+16:p+n]; p+=(n+3)&~3
            if typ==3: return
            if typ==2:
                code=struct.unpack_from('i',body)[0]
                if code: raise OSError(-code,os.strerror(-code))
                return
            yield body

def sockets():
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,4) as s:
        s.settimeout(3)
        req=struct.pack('BBBBI',socket.AF_INET,6,2,0,2)+bytes(48)
        s.send(struct.pack('IHHII',16+len(req),20,0x301,1,0)+req)
        result=[]
        for b in messages(s):
            if len(b)<72 or b[1]!=1: continue
            idle=None; sent_idle=None; received_idle=None; p=72
            while p+4<=len(b):
                n,typ=struct.unpack_from('HH',b,p)
                if n<4: break
                if typ==2 and n>=60:
                    # tcp_info last_data_sent(44), last_data_recv(52), in ms.
                    sent_idle=struct.unpack_from('I',b,p+48)[0]
                    received_idle=struct.unpack_from('I',b,p+56)[0]
                    idle=min(sent_idle, received_idle)
                p+=(n+3)&~3
            local_port,client_port=struct.unpack_from('!HH',b,4)
            result.append(dict(raw=b, local_ip=socket.inet_ntoa(b[8:12]), local_port=local_port,
                               client_ip=socket.inet_ntoa(b[24:28]), client_port=client_port,
                               idle_ms=idle, sent_idle_ms=sent_idle,
                               received_idle_ms=received_idle, inode=struct.unpack_from('I',b,68)[0],
                               queues=struct.unpack_from('II',b,56)))
        return result

def destroy(record):
    b=record['raw']
    req=struct.pack('BBBBI',socket.AF_INET,6,0,0,2)+b[4:52]
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,4) as s:
        s.settimeout(3)
        s.send(struct.pack('IHHII',16+len(req),21,5,2,0)+req)
        list(messages(s))

def capture(interface, client):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    if interface != '*':
        s.bind((interface, 0))
    s.setblocking(False)
    # Ethernet IPv4 TCP to port 443, with payload or SYN. The filter keeps
    # download traffic and pure ACK packets out of Python. 65535 preserves
    # large ClientHello packets (including modern PQ key shares).
    instructions = [
        (0x28, 0, 0, 12), (0x15, 0, 14, 0x0800),
        (0x30, 0, 0, 23), (0x15, 0, 12, 6),
        (0xb1, 0, 0, 14), (0x48, 0, 0, 16), (0x15, 0, 9, 443),
        (0x50, 0, 0, 27), (0x45, 6, 0, 2),  # SYN
        (0x50, 0, 0, 26), (0x74, 0, 0, 2), (0x54, 0, 0, 60),
        (0x0c, 0, 0, 0), (0x07, 0, 0, 0),  # TCP + IP header lengths
        (0x28, 0, 0, 16), (0x2d, 0, 1, 0),
        (0x06, 0, 0, 65535), (0x06, 0, 0, 0)]
    array = (Filter * len(instructions))(*(Filter(*x) for x in instructions))
    program = Program(len(instructions), array)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setsockopt(s.fileno(), socket.SOL_SOCKET, 26,
                       ctypes.byref(program), ctypes.sizeof(program)):
        s.close()
        raise OSError(ctypes.get_errno(), 'cannot attach capture filter')
    return s


def tls_hello(data):
    """Reassemble handshake records, then parse one strictly bounded hello."""
    p = 0
    handshake = bytearray()
    while p < len(data):
        if len(data) - p < 5:
            return None
        if data[p] != 22 or data[p + 1] != 3:
            return ('', [])
        size = int.from_bytes(data[p + 3:p + 5], 'big')
        if size > 18432:
            return ('', [])
        if len(data) - p < 5 + size:
            return None
        handshake.extend(data[p + 5:p + 5 + size])
        p += 5 + size
        if len(handshake) < 4:
            continue
        need = 4 + int.from_bytes(handshake[1:4], 'big')
        if handshake[0] != 1 or need > 65536:
            return ('', [])
        if len(handshake) < need:
            continue
        b = handshake[:need]
        try:
            pos = 38
            pos += 1 + b[pos]
            pos += 2 + int.from_bytes(b[pos:pos + 2], 'big')
            pos += 1 + b[pos]
            end = pos + 2 + int.from_bytes(b[pos:pos + 2], 'big')
            pos += 2
            if end != len(b):
                return ('', [])
            host, alpn = '', []
            while pos < end:
                if pos + 4 > end:
                    return ('', [])
                typ, size = struct.unpack_from('!HH', b, pos)
                pos += 4
                ext = b[pos:pos + size]
                pos += size
                if pos > end:
                    return ('', [])
                if typ == 0:
                    if len(ext) < 5 or int.from_bytes(ext[:2], 'big') != len(ext) - 2:
                        return ('', [])
                    q = 2
                    while q < len(ext):
                        if q + 3 > len(ext):
                            return ('', [])
                        kind, n = ext[q], int.from_bytes(ext[q + 1:q + 3], 'big')
                        q += 3
                        if q + n > len(ext):
                            return ('', [])
                        if kind == 0:
                            host = bytes(ext[q:q + n]).decode('ascii').lower()
                        q += n
                elif typ == 16:
                    if len(ext) < 2 or int.from_bytes(ext[:2], 'big') != len(ext) - 2:
                        return ('', [])
                    q = 2
                    while q < len(ext):
                        n = ext[q]
                        q += 1
                        if not n or q + n > len(ext):
                            return ('', [])
                        alpn.append(bytes(ext[q:q + n]).decode('ascii'))
                        q += n
            return host, alpn
        except (IndexError, UnicodeError, struct.error):
            return ('', [])
    return None


class FlowTracker:
    """Classify full TCP tuples; bounded reassembly tolerates retransmissions."""
    def __init__(self, allowed, client='*'):
        self.allowed = allowed
        self.client = client
        self.tracked = {}
        self.partial = {}

    def feed(self, packet, now):
        if len(packet) < 54 or packet[12:14] != b'\x08\x00' or packet[14] >> 4 != 4:
            return
        ihl = (packet[14] & 15) * 4
        tcp = 14 + ihl
        total = 14 + int.from_bytes(packet[16:18], 'big')
        if ihl < 20 or len(packet) < total or total < tcp + 20 or packet[23] != 6:
            return
        if int.from_bytes(packet[20:22], 'big') & 0x3fff:
            return
        src = socket.inet_ntoa(packet[26:30])
        dst = socket.inet_ntoa(packet[30:34])
        cp, dp = struct.unpack_from('!HH', packet, tcp)
        if dp != 443 or (self.client != '*' and src != self.client):
            return
        key = (src, cp, dst, dp)
        flags = packet[tcp + 13]
        if flags & 2:
            self.tracked.pop(key, None)
            self.partial.pop(key, None)
        header = (packet[tcp + 12] >> 4) * 4
        if header < 20 or tcp + header > total:
            return
        payload = packet[tcp + header:total]
        if not payload or key in self.tracked:
            return
        seq = int.from_bytes(packet[tcp + 4:tcp + 8], 'big')
        if key not in self.partial:
            if not payload.startswith(b'\x16\x03') or len(self.partial) >= 512:
                return
            self.partial[key] = [seq, {}, now]
        start, fragments, when = self.partial[key]
        offset = (seq - start) & 0xffffffff
        if offset + len(payload) > 65536 or len(fragments) >= 128:
            self.partial.pop(key, None)
            return
        if len(payload) > len(fragments.get(offset, b'')):
            fragments[offset] = payload
        data = bytearray()
        for off, part in sorted(fragments.items()):
            if off > len(data):
                break
            data.extend(part[max(0, len(data) - off):])
        parsed = tls_hello(data)
        if parsed is not None:
            host, alpn = parsed
            if google_host(host, self.allowed) and 'h2' in alpn and len(self.tracked) < 4096:
                self.tracked[key] = (host, now)
            self.partial.pop(key, None)

    def prune(self, mapping, now):
        self.partial = {k: v for k, v in self.partial.items() if now - v[2] < 10}
        live = set(mapping.values())
        for key, (host, seen) in list(self.tracked.items()):
            if key in live:
                self.tracked[key] = (host, now)
            elif now - seen > 30:
                del self.tracked[key]


def parse_nat(lines, client):
    result = {}
    for line in lines:
        if ' tcp ' not in line or ' ESTABLISHED ' not in line:
            continue
        fields = {}
        for token in line.split():
            if '=' in token:
                key, value = token.split('=', 1)
                fields.setdefault(key, []).append(value)
        try:
            src, dst = fields['src'][0], fields['dst'][0]
            cp, dp = int(fields['sport'][0]), int(fields['dport'][0])
            if dp != 443 or (client != '*' and src != client):
                continue
            # Reply tuple must lead back to the original client, through redir.
            if fields['dst'][1] != src or int(fields['dport'][1]) != cp:
                continue
            key = (src, cp, fields['src'][1], int(fields['sport'][1]))
            result[key] = (src, cp, dst, dp)
        except (KeyError, IndexError, ValueError):
            continue
    return result


def nat_map(client):
    for path in ('/proc/net/nf_conntrack', '/proc/net/ip_conntrack'):
        try:
            with open(path) as file:
                return parse_nat(file, client)
        except FileNotFoundError:
            continue
    raise OSError('conntrack proc interface unavailable')


def redir_owners(state, candidates):
    # Discover live redir processes instead of relying on one firmware's PID
    # file format. This includes every thread and retained KCP generation.
    inodes = {}
    for path in glob.glob('/proc/[0-9]*/comm'):
        pid = path.split('/')[2]
        try:
            with open(path) as file:
                if file.read().strip() != 'ssr-redir':
                    continue
            if os.path.basename(os.readlink('/proc/' + pid + '/exe')) != 'ssr-redir':
                continue
        except OSError:
            continue
        for fd in glob.glob('/proc/' + pid + '/fd/*'):
            try:
                name = os.readlink(fd)
                if name.startswith('socket:['):
                    inode = int(name[8:-1])
                    if inode in candidates:
                        inodes[inode] = (int(pid), int(fd.rsplit('/', 1)[1]))
            except (OSError, ValueError):
                continue
    return inodes


def expiry_key(record, mapping, tracked, limit):
    key = mapping.get((record['client_ip'], record['client_port'],
                       record['local_ip'], record['local_port']))
    if (key not in tracked or record.get('sent_idle_ms') is None or
            record['sent_idle_ms'] < limit * 1000 or record['queues'] != (0, 0)):
        return None
    return key


def run(args):
    with open(args.config) as file:
        config = json.load(file)
    client = config.get('client', '*')
    limit = int(config.get('idle_seconds', 8))
    if not 8 <= limit <= 300:
        raise ValueError('idle_seconds must be 8..300')
    close_method = config.get('close_method', 'auto')
    if close_method == 'auto':
        close_method = 'pidfd_shutdown' if os.uname().machine == 'aarch64' else 'inet_diag'
    if close_method not in ('inet_diag', 'pidfd_shutdown'):
        raise ValueError('unsupported close_method')
    if close_method == 'pidfd_shutdown' and os.uname().machine != 'aarch64':
        raise ValueError('pidfd backend requires tested aarch64 architecture')
    tracker = FlowTracker(config['host_suffixes'], client)
    cap = capture(config.get('interface', '*'), client)
    syslog.openlog('google-idle-guard')
    emit('started', client=client, interface=config.get('interface', '*'),
         response_idle_seconds=limit, check_seconds=1, close_method=close_method)
    next_check = 0
    while True:
        now = time.monotonic()
        ready, _, _ = select.select([cap], [], [], max(0, min(1, next_check - now)))
        if ready:
            for _ in range(128):
                try:
                    packet = cap.recv(65535)
                except BlockingIOError:
                    break
                tracker.feed(packet, time.monotonic())
        now = time.monotonic()
        if now < next_check:
            continue
        next_check = now + 1
        try:
            if not tracker.tracked:
                tracker.prune({}, now)
                continue
            mapping = nat_map(client)
            tracker.prune(mapping, now)
            candidates = [(record, expiry_key(record, mapping, tracker.tracked, limit))
                          for record in sockets()]
            candidates = [(r, k) for r, k in candidates if k is not None]
            if not candidates:
                continue
            owners = redir_owners(config.get('state_directory'), {r['inode'] for r, k in candidates})
            for record, key in candidates:
                if record['inode'] not in owners:
                    continue
                if args.only_port and record['client_port'] != args.only_port:
                    continue
                host = tracker.tracked[key][0]
                fields = dict(host=host, client_ip=key[0], client_port=key[1],
                              response_idle_ms=record['sent_idle_ms'])
                if args.dry_run:
                    emit('would_expire', **fields)
                    continue
                # Re-read NAT immediately before closing. Snapshot retention is
                # only for classification, never permission to close a socket.
                if expiry_key(record, nat_map(client), tracker.tracked, limit) != key:
                    continue
                try:
                    if close_method == 'pidfd_shutdown':
                        if not shutdown_owned_socket(record, owners[record['inode']], limit):
                            continue
                    else:
                        destroy(record)
                except OSError as ex:
                    if ex.errno in (2, 3, 9, 107):
                        continue
                    emit('close_error', error=str(ex), **fields)
                    continue
                emit('expired', **fields)
                tracker.tracked.pop(key, None)
        except (OSError, ValueError) as ex:
            emit('check_error', error=str(ex))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/google-idle-guard.json')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--only-port', type=int)
    run(parser.parse_args())
