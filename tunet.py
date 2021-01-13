# -*- coding: UTF-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


def closure():
    import base64
    import functools
    import hashlib
    import hmac
    import json
    import sys
    import time

    if sys.version_info[0] == 2:
        import urllib
        import urllib2
        import urlparse
        int2byte = chr
        urlencode = urllib.urlencode
        parse_qs = urlparse.parse_qs
        urlparse = urlparse.urlparse
        Request = urllib2.Request
        urlopen = urllib2.urlopen
    else:
        import struct
        import urllib.parse
        import urllib.request
        int2byte = struct.Struct(">B").pack
        urlencode = urllib.parse.urlencode
        parse_qs = urllib.parse.parse_qs
        urlparse = urllib.parse.urlparse
        Request = urllib.request.Request
        urlopen = urllib.request.urlopen

    _URL_SRUN_PORTAL = 'https://auth{:d}.tsinghua.edu.cn/cgi-bin/srun_portal'
    _URL_GET_CHALLENGE = _URL_SRUN_PORTAL.replace(
            'srun_portal', 'get_challenge')
    _URL_QUERY_AC_ID = 'http://usereg.tsinghua.edu.cn/ip_login_import.php'
    _URL_AC_DETECT = 'https://auth{:d}.tsinghua.edu.cn/ac_detect.php?ac_id=1'
    _URL_NET_LOGIN = 'https://net.tsinghua.edu.cn/do_login.php'
    _URL_USER_INFO = 'https://{:s}.tsinghua.edu.cn/rad_user_info.php'
    _SHORT_TIMEOUT = 5

    _JSONP_FUNCNAME = 'callback'

    def current_timestamp():
        return int(time.time() * 1000)

    def xEncode(str, key):
        def s(a, b):
            c = len(a)
            v = []
            for i in range(0, c, 4):
                v.append(
                    ord(a[i]) |
                    lshift(0 if i + 1 >= len(a) else ord(a[i + 1]), 8) |
                    lshift(0 if i + 2 >= len(a) else ord(a[i + 2]), 16) |
                    lshift(0 if i + 3 >= len(a) else ord(a[i + 3]), 24)
                )
            if b:
                v.append(c)
            return v

        def l(a, b):
            d = len(a)
            c = lshift(d - 1, 2)
            if b:
                m = a[d - 1]
                if m < c - 3 or m > c:
                    return None
                c = m
            for i in range(d):
                a[i] = int2byte(a[i] & 0xff) \
                    + int2byte(rshift(a[i], 8) & 0xff) \
                    + int2byte(rshift(a[i], 16) & 0xff) \
                    + int2byte(rshift(a[i], 24) & 0xff)
            if b:
                return b''.join(a)[:c]
            else:
                return b''.join(a)

        def rshift(x, n):
            return x >> n

        def lshift(x, n):
            return (x << n) & ((1 << 32) - 1)

        if str == '':
            return ''
        v = s(str, True)
        k = s(key, False)
        while len(k) < 4:
            k.append(None)
        n = len(v) - 1
        z = v[n]
        c = 0x86014019 | 0x183639A0
        q = 6 + 52 // (n + 1)
        d = 0
        while 0 < q:
            q -= 1
            d = d + c & (0x8CE0D9BF | 0x731F2640)
            e = rshift(d, 2) & 3
            for p in range(n):
                y = v[p + 1]
                m = rshift(z, 5) ^ lshift(y, 2)
                m += rshift(y, 3) ^ lshift(z, 4) ^ (d ^ y)
                m += k[(p & 3) ^ e] ^ z
                z = v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF)
            p = n
            y = v[0]
            m = rshift(z, 5) ^ lshift(y, 2)
            m += rshift(y, 3) ^ lshift(z, 4) ^ (d ^ y)
            m += k[(p & 3) ^ e] ^ z
            z = v[n] = v[n] + m & (0xBB390742 | 0x44C6F8BD)
        return l(v, False)

    def base64_encode(s):
        a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        b = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
        s = base64.b64encode(s)
        return s.decode().translate(
                {ord(x): y for (x, y) in zip(a, b)}).encode()

    def get_ac_id(ip):
        url = _URL_QUERY_AC_ID
        data = {'actionType': 'searchNasId', 'ip': ip}
        req = Request(url, data=urlencode(data).encode())
        res = urlopen(req, timeout=_SHORT_TIMEOUT)
        assert 200 == res.getcode()
        text = res.read().decode('utf-8').strip()
        if text == 'fail':
            return 1
        else:
            return int(text)

    def read_callback(res):
        assert 200 == res.getcode()
        page = res.read().decode('utf-8').strip()
        assert page.startswith(_JSONP_FUNCNAME + '({') and page.endswith('})')
        page = page[len(_JSONP_FUNCNAME) + 1:-1]
        args = json.loads(page)
        return args

    def _get_challenge(ipv, username, ip):
        url = _URL_GET_CHALLENGE.format(ipv)
        data = {
            'callback': _JSONP_FUNCNAME,
            'username': username,
            'ip': ip,
            'double_stack': '1',
            '_': current_timestamp(),
        }
        req = Request(url + '?' + urlencode(data))
        res = urlopen(req, timeout=_SHORT_TIMEOUT)
        challenge = read_callback(res)
        assert challenge.get('res') == 'ok', challenge.get('error')
        return challenge

    def _auth_login(ipv, username, password, net=False, ip=''):
        if not net:
            username = '{:s}@tsinghua'.format(username)\

        url = _URL_SRUN_PORTAL.format(ipv)
        challenge = _get_challenge(ipv, username, ip)
        ip = ip or challenge['online_ip']
        ac_id = get_ac_id(ip)
        n = 200
        type = 1
        token = challenge['challenge']
        hmd5 = hmac.new(token.encode(), None, hashlib.md5).hexdigest()
        info = '{SRBX1}' + base64_encode(xEncode(json.dumps({
            'username': username,
            'password': password,
            'ip': ip,
            'acid': ac_id,
            'enc_ver': 'srun_bx1',
        }), token)).decode()
        chksum = hashlib.sha1((
            token + username +
            token + hmd5 +
            token + '{:d}'.format(ac_id) +
            token + ip +
            token + '{:d}'.format(n) +
            token + '{:d}'.format(type) +
            token + info
        ).encode()).hexdigest()

        data = {
            'callback': _JSONP_FUNCNAME,
            'action': 'login',
            'username': username,
            'password': '{MD5}' + hmd5,
            'ac_id': ac_id,
            'ip': ip,
            'double_stack': '1',
            'info': info,
            'chksum': chksum,
            'n': n,
            'type': type,
            '_': current_timestamp(),
        }
        req = Request(url + '?' + urlencode(data))
        res = urlopen(req, timeout=_SHORT_TIMEOUT)
        return read_callback(res)

    def _auth_checklogin(ipv):
        url = _URL_AC_DETECT.format(ipv)
        req = Request(url)
        res = urlopen(req)
        assert 200 == res.getcode()
        url = res.geturl()
        username = parse_qs(urlparse(url).query).get('username')
        if not username:
            return {}
        else:
            return {
                'username': username[0],
            }

    def _auth_logout(ipv, ip=''):
        url = _URL_SRUN_PORTAL.format(ipv)
        username = 'placeholder'
        challenge = _get_challenge(ipv, username, ip)

        ac_id = 1
        n = 200
        type = 1
        token = challenge['challenge']
        info = '{SRBX1}' + base64_encode(xEncode(json.dumps({
            'username': username,
            'ip': ip,
            'acid': ac_id,
            'enc_ver': 'srun_bx1',
        }), token)).decode()
        chksum = hashlib.sha1((
            token + username +
            token + '{:d}'.format(ac_id) +
            token + ip +
            token + '{:d}'.format(n) +
            token + '{:d}'.format(type) +
            token + info
        ).encode()).hexdigest()
        data = {
            'callback': _JSONP_FUNCNAME,
            'action': 'logout',
            'username': username,
            'ac_id': 1,
            'ip': ip,
            'double_stack': '1',
            'info': info,
            'chksum': chksum,
            'n': n,
            'type': type,
            '_': current_timestamp(),
        }
        req = Request(url + '?' + urlencode(data))
        res = urlopen(req, timeout=_SHORT_TIMEOUT)
        return read_callback(res)

    def _subdomain_info(subdomain):
        url = _URL_USER_INFO.format(subdomain)
        req = Request(url)
        res = urlopen(req)
        assert 200 == res.getcode()
        line = res.read().decode('utf-8').strip()
        if not line:
            return {}
        else:
            words = [s.strip() for s in line.split(',')]
            return {
                'username': words[0],
                'time_login': int(words[1]),
                'time_query': int(words[2]),
                'session_incoming': int(words[3]),
                'session_outgoing': int(words[4]),
                'cumulative_incoming': int(words[6]),
                'cumulative_time': int(words[7]),
                'ipv4_address': words[8],
                'balance': words[11],
            }

    def _net_login(username, password):
        url = _URL_NET_LOGIN
        data = {
            'action': 'login',
            'username': username,
            'password': '{MD5_HEX}' + hashlib.md5(
                        password.encode('latin1')).hexdigest(),
            'ac_id': '1',
        }
        req = Request(url, data=urlencode(data).encode())
        res = urlopen(req)
        assert 200 == res.getcode()
        return {'msg': res.read().decode('utf-8')}

    def _net_logout():
        url = _URL_NET_LOGIN
        data = {'action': 'logout'}
        req = Request(url, data=urlencode(data).encode())
        res = urlopen(req)
        assert 200 == res.getcode()
        return {'msg': res.read().decode('utf-8')}

    class Tunet(object):
        pass

    auth4 = Tunet()
    auth4.login = functools.partial(_auth_login, 4)
    auth4.logout = functools.partial(_auth_logout, 4)
    auth4.checklogin = functools.partial(_auth_checklogin, 4)

    auth6 = Tunet()
    auth6.login = functools.partial(_auth_login, 6)
    auth6.logout = functools.partial(_auth_logout, 6)
    auth6.checklogin = functools.partial(_auth_checklogin, 6)

    net = Tunet()
    net.login = _net_login
    net.logout = _net_logout
    net.checklogin = functools.partial(_subdomain_info, 'net')

    return auth4, auth6, net


auth4, auth6, net = closure()
del closure
