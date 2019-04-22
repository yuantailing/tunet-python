# -*- coding: UTF-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import base64
import copy
import hashlib
import json
import six

from six.moves.urllib import parse, request


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
            a[i] = six.int2byte(a[i] & 0xff) \
                + six.int2byte(rshift(a[i], 8) & 0xff) \
                + six.int2byte(rshift(a[i], 16) & 0xff) \
                + six.int2byte(rshift(a[i], 24) & 0xff)
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
    y = v[0]
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


def get(url, data, callback, dataType):
    if dataType == 'jsonp':
        data = copy.deepcopy(data)
        data['callback'] = 'callback'
        _data = parse.urlencode(data)
        req = request.Request(url + '?' + _data if _data else url)
        res = request.urlopen(req, timeout=5)  # TODO: remove hardcoded timeout
        assert 200 == res.getcode()
        page = res.read().decode('utf-8').strip()
        assert page.startswith(data['callback'] + '({') and page.endswith('})')
        page = page[len(data['callback']) + 1:-1]
        page = json.loads(page)
        if callback:
            page = callback(page)
        return page
    elif dataType == 'raw':
        data = parse.urlencode(data)
        req = request.Request(url + '?' + data if data else url)
        res = request.urlopen(req, timeout=5)
        assert 200 == res.getcode()
        page = res.read().decode('utf-8')
        if callback:
            page = callback(page)
        return page
    else:
        raise NotImplementedError
    return None


def base64_encode(s):
    a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    b = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
    s = base64.b64encode(s)
    return s.decode().translate({ord(x): y for (x, y) in zip(a, b)}).encode()


def getJSON(url, data, callback):
    if 'srun_portal' in url or 'get_challenge' in url:
        enc = 'srun_bx1'
        n = 200
        type = 1
        _data = data
        if data.get('action') == 'login':
            def foo(data):
                assert data.get('res') == 'ok', data.get('error')
                token = data.get('challenge')
                _data['info'] = '{SRBX1}' + base64_encode(xEncode(json.dumps({
                    'username': _data.get('username'),
                    'password': _data.get('password'),
                    'ip': _data.get('ip'),
                    'acid': _data.get('ac_id'),
                    'enc_ver': enc,
                }), token)).decode()
                hmd5 = hashlib.md5(data.get('password', 'undefined')
                                       .encode('latin1')).hexdigest()
                _data['password'] = '{MD5}' + hmd5
                _data['chksum'] = hashlib.sha1((
                        token + _data.get('username') +
                        token + hmd5 +
                        token + '{}'.format(_data.get('ac_id')) +
                        token + _data.get('ip') +
                        token + '{}'.format(n) +
                        token + '{}'.format(type) +
                        token + _data.get('info')
                ).encode('latin1')).hexdigest()
                _data['n'] = n
                _data['type'] = type
                return get(url, _data, callback, 'jsonp')
            return getJSON(
                url.replace('srun_portal', 'get_challenge'),
                {
                    'username': _data.get('username'),
                    'ip': _data.get('ip'),
                    'double_stack': '1',
                },
                foo,
            )
        elif data.get('action') == 'logout':
            def foo(data):
                assert data.get('res') == 'ok', data.get('error')
                token = data.get('challenge')
                _data['info'] = '{SRBX1}' + base64_encode(xEncode(json.dumps({
                    'username': _data.get('username'),
                    'ip': _data.get('ip'),
                    'acid': _data.get('ac_id'),
                    'enc_ver': enc,
                }), token)).decode()
                _data['chksum'] = hashlib.sha1((
                        token + _data.get('username') +
                        token + '{}'.format(_data.get('ac_id')) +
                        token + _data.get('ip') +
                        token + '{}'.format(n) +
                        token + '{}'.format(type) +
                        token + _data.get('info')
                ).encode('latin1')).hexdigest()
                _data['n'] = n
                _data['type'] = type
                return get(url, _data, callback, 'jsonp')
            return getJSON(
                url.replace('srun_portal', 'get_challenge'),
                {
                    'username': _data.get('username'),
                    'ip': _data.get('ip'),
                    'double_stack': '1',
                },
                foo,
            )
        else:
            return get(url, data, callback, 'jsonp')
    return get(url, data, callback, 'jsonp')


if __name__ == '__main__':
    getJSON(
        'https://auth4.tsinghua.edu.cn/cgi-bin/srun_portal',
        {
            'action': 'login',
            'username': 'username',
            'password': 'password',
            'ac_id': '1',
            'ip': '',
            'double_stack': '1',
        },
        print,
    )
