#!/usr/bin/env python3
"""Interactive RTSP diagnostic client: TCP interleaved, UDP unicast, multicast."""
import argparse
import getpass
import hashlib
import ipaddress
import re
import secrets
import socket
import time
import random
from urllib.parse import urlparse, urljoin


def parse_headers(text):
    result = {}
    for line in text.split('\r\n')[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            # Preserve the first value (notably WWW-Authenticate).
            result.setdefault(k.strip().lower(), v.strip())
    return result


def parse_digest(value):
    if not value:
        return None
    m = re.match(r'\s*Digest\s+(.*)', value, re.I)
    if not m:
        return None
    params = {}
    for x in re.finditer(r'([A-Za-z][\w-]*)\s*=\s*("(?:\\.|[^"])*"|[^,]*)', m.group(1)):
        v = x.group(2).strip()
        if v.startswith('"') and v.endswith('"'):
            v = re.sub(r'\\(.)', r'\1', v[1:-1])
        params[x.group(1).lower()] = v
    return params


def digest_hash(algorithm, value):
    name = (algorithm or 'MD5').upper().replace('-SESS', '').replace('-', '')
    if name == 'MD5':
        return hashlib.md5(value.encode()).hexdigest()
    if name == 'SHA256':
        return hashlib.sha256(value.encode()).hexdigest()
    raise ValueError(f'Unsupported Digest algorithm: {algorithm}')


class RTSPClient:
    def __init__(self, url, username=None, password=None, timeout=5):
        p = urlparse(url)
        if p.scheme.lower() != 'rtsp' or not p.hostname:
            raise ValueError('URL must be rtsp://...')
        self.url, self.host, self.port = url, p.hostname, p.port or 554
        self.username, self.password, self.timeout = username, password, timeout
        self.sock = None
        self.cseq = 0
        self.session = None
        self.challenge = None
        self.nc = 0
        self.cnonce = secrets.token_hex(8)
        self.sdp = ''
        self.tracks = {}
        self.aggregate_url = url
        self.tcp_channels = {}
        self.transports = {}
        self.udp = {}          # media -> (rtp_socket, rtcp_socket)
        self.multicast = {}    # media -> (group, membership request, sockets)
        self.client_port = 10000 + random.randrange(2,1001,2)

    def connect(self):
        if self.sock is None:
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
            self.sock.settimeout(self.timeout)
            print(f'[CONNECTED] {self.host}:{self.port}')

    def _exact(self, n):
        chunks = []
        while n:
            b = self.sock.recv(n)
            if not b:
                raise ConnectionError('RTSP peer closed the connection')
            chunks.append(b)
            n -= len(b)
        return b''.join(chunks)

    def _read_response(self):
        # Skip RTP/RTCP interleaved frames arriving before an RTSP response.
        while True:
            first = self._exact(1)
            if first == b'$':
                channel = self._exact(1)[0]
                length = int.from_bytes(self._exact(2), 'big')
                self._exact(length)
                print(f'[INTERLEAVED while awaiting response] channel={channel}, {length} bytes')
                continue
            data = bytearray(first)
            while not data.endswith(b'\r\n\r\n'):
                data.extend(self._exact(1))
                if len(data) > 65536:
                    raise RuntimeError('RTSP headers too large')
            head = data.decode('latin-1')
            headers = parse_headers(head)
            length = int(headers.get('content-length', '0') or '0')
            body = self._exact(length) if length else b''
            m = re.match(r'RTSP/\d+\.\d+\s+(\d+)\s*(.*)', head)
            if not m:
                raise RuntimeError(f'Invalid RTSP response: {head!r}')
            return int(m.group(1)), m.group(2).strip(), headers, body

    def _authorization(self, method, uri):
        c = self.challenge
        if not c or not self.username:
            return None
        realm, nonce = c.get('realm', ''), c.get('nonce', '')
        algorithm = c.get('algorithm', 'MD5')
        qops = [q.strip().lower() for q in c.get('qop', '').split(',')]
        qop = 'auth' if 'auth' in qops else None
        ha1 = digest_hash(algorithm, f'{self.username}:{realm}:{self.password or ""}')
        if algorithm.upper().endswith('-SESS'):
            ha1 = digest_hash(algorithm, f'{ha1}:{nonce}:{self.cnonce}')
        ha2 = digest_hash(algorithm, f'{method}:{uri}')
        fields = [f'username="{self.username}"', f'realm="{realm}"',
                  f'nonce="{nonce}"', f'uri="{uri}"']
        if qop:
            self.nc += 1
            nc = f'{self.nc:08x}'
            response = digest_hash(algorithm, f'{ha1}:{nonce}:{nc}:{self.cnonce}:{qop}:{ha2}')
            fields += [f'response="{response}"', f'algorithm={algorithm}',
                       f'qop={qop}', f'nc={nc}', f'cnonce="{self.cnonce}"']
        else:
            response = digest_hash(algorithm, f'{ha1}:{nonce}:{ha2}')
            fields += [f'response="{response}"', f'algorithm={algorithm}']
        if c.get('opaque') is not None:
            fields.append(f'opaque="{c["opaque"]}"')
        return 'Digest ' + ', '.join(fields)

    def request(self, method, uri=None, headers=None):
        uri = uri or self.url
        for attempt in range(2):
            self.connect()
            self.cseq += 1
            h = {'CSeq': str(self.cseq), 'User-Agent': 'python-rtsp-test-client/1.0'}
            if self.session:
                h['Session'] = self.session
            if headers:
                h.update(headers)
            auth = self._authorization(method, uri)
            if auth:
                h['Authorization'] = auth
            request = f'{method} {uri} RTSP/1.0\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in h.items()) + '\r\n'
            print(f'\n>>> {method} {uri}')
            for line in request.split('\r\n'):
                if line.lower().startswith('authorization:'):
                    print('Authorization: Digest [redacted]')
                elif line:
                    print(line)
            self.sock.sendall(request.encode('latin-1'))
            status, reason, rh, body = self._read_response()
            print(f'<<< RTSP/1.0 {status} {reason}')
            for k, v in rh.items():
                print(f'{k}: {v}')
            if body:
                print(body.decode('utf-8', errors='replace'))
            if status == 401 and attempt == 0 and self.username and self.password is not None:
                ch = parse_digest(rh.get('www-authenticate'))
                if ch:
                    self.challenge = ch
                    print('[AUTH] Retrying with Digest authentication')
                    continue
            if rh.get('session'):
                self.session = rh['session'].split(';', 1)[0].strip()
            return status, rh, body
        return status, rh, body

    def options(self):
        return self.request('OPTIONS')[0]

    def describe(self):
        status, headers, body = self.request('DESCRIBE', headers={'Accept': 'application/sdp'})
        if status != 200:
            print(f'[ERROR] DESCRIBE status={status}')
            return status
        self.sdp = body.decode('utf-8', errors='replace')
        self.tracks = {}
        base = headers.get('content-base') or headers.get('content-location') or self.url
        self.aggregate_url = base
        media = None
        for raw in self.sdp.splitlines():
            line = raw.strip()
            if line.startswith('m='):
                name = line[2:].split()[0].lower()
                media = name if name in ('video', 'audio') else None
            elif line.startswith('a=control:'):
                control = line[len('a=control:'):].strip()
                if control == '*':
                    self.aggregate_url = base
                elif media:
                    self.tracks[media] = urljoin(base, control)
        print('--- SDP ---\n' + self.sdp.rstrip() + '\n--- Tracks ---')
        print('aggregate:', self.aggregate_url)
        for k, v in self.tracks.items():
            print(f'{k}: {v}')
        return status

    @staticmethod
    def _udp_pair():
        pair = []
        for _ in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', 0))
            s.settimeout(0.2)
            pair.append(s)
        return tuple(pair)

    def _cleanup_media(self, media):
        pair = self.udp.pop(media, None)
        if pair:
            for s in pair:
                s.close()
        group_info = self.multicast.pop(media, None)
        if group_info:
            group, mreq, pair = group_info
            for s in pair:
                try:
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                except OSError:
                    pass
                s.close()

    def setup(self, media, transport='tcp'):
        if media not in self.tracks:
            print(f'[ERROR] No {media} track; run describe first')
            return None
        if transport not in ('tcp', 'udp', 'multicast'):
            print('Transport must be tcp, udp, or multicast')
            return None
        self._cleanup_media(media)
        headers = {}
        if transport == 'tcp':
            ch = 0 if media == 'video' else 2
            headers['Transport'] = f'RTP/AVP/TCP;unicast;interleaved={ch}-{ch+1}'
        elif transport == 'udp':
            pair = self._udp_pair()
            self.udp[media] = pair
            headers['Transport'] = f'RTP/AVP;unicast;client_port={pair[0].getsockname()[1]}-{pair[1].getsockname()[1]}'
        else:
            #headers['Transport'] = f'RTP/AVP;multicast;client_port={self.client_port}-{self.client_port+1}'
            headers['Transport'] = 'RTP/AVP;multicast'
        status, rh, _ = self.request('SETUP', self.tracks[media], headers=headers)
        tr = rh.get('transport', '')
        print(f'[{media.upper()} SETUP / {transport.upper()}] status={status}')
        if tr:
            print('Transport response:', tr)
        if status != 200:
            self._cleanup_media(media)
            print('[ERROR] SETUP failed; not marking this track as configured')
            return status
        self.transports[media] = transport
        if transport == 'tcp':
            ch = 0 if media == 'video' else 2
            self.tcp_channels[media] = (ch, ch + 1)
        elif transport == 'multicast':
            self._join_multicast(media, tr)
        return status

    def _join_multicast(self, media, transport_header):
        params = {}
        for item in transport_header.split(';')[1:]:
            if '=' in item:
                k, v = item.split('=', 1)
                params[k.strip().lower()] = v.strip().strip('"')
        group, ports = params.get('destination'), params.get('port')
        if not group or not ports:
            print('[WARN] Multicast response lacks destination= or port=; cannot join automatically')
            return
        try:
            if not ipaddress.ip_address(group).is_multicast:
                print(f'[WARN] {group} is not a multicast address')
                return
            pp = [int(x) for x in ports.split('-')]
            ports_pair = (pp[0], pp[1] if len(pp) > 1 else pp[0] + 1)
            pair = []
            mreq = socket.inet_aton(group) + socket.inet_aton('0.0.0.0')
            for port in ports_pair:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                s.bind(('', port))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                s.settimeout(0.2)
                pair.append(s)
            self.multicast[media] = (group, mreq, tuple(pair))
            print(f'[MULTICAST] joined {group}, RTP/RTCP ports {ports_pair[0]}/{ports_pair[1]}')
        except (OSError, ValueError) as e:
            print(f'[WARN] Could not join multicast group: {e}')

    def play(self):
        if not self.session:
            print('[WARN] No Session ID; issue SETUP first')
        status, _, _ = self.request('PLAY', self.aggregate_url, headers={'Range': 'npt=0.000-'})
        print(f'[PLAY] status={status}')
        return status

    def receive(self, seconds=5):
        end = time.monotonic() + max(0.1, seconds)
        counts = {}
        print(f'[RECEIVE] {seconds:g} seconds')
        while time.monotonic() < end:
            activity = False
            for media, pair in list(self.udp.items()):
                for kind, s in zip(('RTP', 'RTCP'), pair):
                    try:
                        data, addr = s.recvfrom(65535)
                        counts[(media, kind)] = counts.get((media, kind), 0) + 1
                        print(f'[UDP {media} {kind}] {len(data)} bytes from {addr}')
                        activity = True
                    except socket.timeout:
                        pass
                    except OSError as e:
                        print(f'[UDP {media}] {e}')
            for media, (_, _, pair) in list(self.multicast.items()):
                for kind, s in zip(('RTP', 'RTCP'), pair):
                    try:
                        data, addr = s.recvfrom(65535)
                        counts[(media, kind)] = counts.get((media, kind), 0) + 1
                        print(f'[MULTICAST {media} {kind}] {len(data)} bytes from {addr}')
                        activity = True
                    except socket.timeout:
                        pass
                    except OSError as e:
                        print(f'[MULTICAST {media}] {e}')
            # Read TCP interleaved frames. This intentionally expects media data,
            # not an RTSP response, while receive is active.
            if self.sock and self.tcp_channels:
                old_timeout = self.sock.gettimeout()
                try:
                    self.sock.settimeout(0.03)
                    first = self.sock.recv(1)
                    if first == b'$':
                        ch = self._exact(1)[0]
                        size = int.from_bytes(self._exact(2), 'big')
                        self._exact(size)
                        media = next((m for m, pair in self.tcp_channels.items() if ch in pair), 'unknown')
                        counts[(media, 'TCP-interleaved')] = counts.get((media, 'TCP-interleaved'), 0) + 1
                        print(f'[TCP {media}] channel={ch}, {size} bytes')
                        activity = True
                    elif first:
                        print('[WARN] Non-interleaved byte encountered; TCP receive stopped to avoid consuming RTSP data')
                        break
                except socket.timeout:
                    pass
                except OSError as e:
                    print(f'[TCP] {e}')
                    break
                finally:
                    if self.sock:
                        self.sock.settimeout(old_timeout)
            if not activity:
                time.sleep(0.02)
        print('[RECEIVE SUMMARY]')
        if not counts:
            print('No RTP/RTCP packets observed')
        for (media, kind), count in sorted(counts.items()):
            print(f'{media} {kind}: {count} packets')

    def teardown(self):
        if self.sock:
            try:
                status, _, _ = self.request('TEARDOWN', self.aggregate_url)
                print(f'[TEARDOWN] status={status}')
            except (OSError, ConnectionError, RuntimeError) as e:
                print(f'[WARN] TEARDOWN failed: {e}')
        for media in list(self.udp.keys()) + list(self.multicast.keys()):
            self._cleanup_media(media)
        self.tcp_channels.clear()
        self.transports.clear()
        self.session = None

    def status(self):
        print('Connected:', bool(self.sock))
        print('Session:', self.session or '(none)')
        print('Aggregate URL:', self.aggregate_url)
        print('Tracks:', self.tracks)
        print('Configured transports:', self.transports)

    def close(self):
        for media in list(set(self.udp) | set(self.multicast)):
            self._cleanup_media(media)
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        print('[CLOSED]')


def main():
    ap = argparse.ArgumentParser(description='Interactive RTSP test client')
    ap.add_argument('url', help='e.g. rtsp://192.168.1.100/stream')
    ap.add_argument('--username')
    ap.add_argument('--password', help='Password; prefer interactive prompt')
    ap.add_argument('--timeout', type=float, default=5.0)
    args = ap.parse_args()
    password = args.password
    if args.username and password is None:
        password = getpass.getpass('RTSP password: ')
    client = RTSPClient(args.url, args.username, password, args.timeout)
    print('Commands: options | describe | setup <video|audio> <tcp|udp|multicast>')
    print('          play | receive [seconds] | teardown | status | quit')
    try:
        client.connect()
        while True:
            try:
                parts = input('rtsp> ').strip().split()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not parts:
                continue
            cmd, a = parts[0].lower(), parts[1:]
            try:
                if cmd == 'options':
                    client.options()
                elif cmd == 'describe':
                    client.describe()
                elif cmd == 'setup':
                    if len(a) != 2 or a[0].lower() not in ('video', 'audio') or a[1].lower() not in ('tcp', 'udp', 'multicast'):
                        print('Usage: setup <video|audio> <tcp|udp|multicast>')
                    else:
                        client.setup(a[0].lower(), a[1].lower())
                elif cmd == 'play':
                    client.play()
                elif cmd == 'receive':
                    client.receive(float(a[0]) if a else 5.0)
                elif cmd == 'teardown':
                    client.teardown()
                elif cmd == 'status':
                    client.status()
                elif cmd in ('quit', 'exit'):
                    break
                else:
                    print('Unknown command')
            except (OSError, ConnectionError, RuntimeError, ValueError) as e:
                print(f'[ERROR] {e}')
    finally:
        client.close()


if __name__ == '__main__':
    main()

