# -*- coding: UTF-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import hashlib

from . import lib
from six.moves.urllib import parse, request


def subdomain_info(subdomain):
    def info():
        line = lib.get('https://{:s}.tsinghua.edu.cn/rad_user_info.php'
                       .format(subdomain), {}, None, 'raw')
        words = [s.strip() for s in line.split(',')]
        if not words:
            return {}
        else:
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
    return info


def auth_login(ipv):
    def login(username, password, net=False):
        if not net:
            username = '{}@tsinghua'.format(username)
        res = lib.getJSON(
            'https://auth{:d}.tsinghua.edu.cn/cgi-bin/srun_portal'.format(ipv),
            {
                'action': 'login',
                'username': username,
                'password': password,
                'ac_id': '1',
                'ip': '',
                'double_stack': '1',
            },
            None,
        )
        return res
    return login


def auth_logout(ipv):
    def logout():
        username = auth_checklogin(ipv)().get('username')
        if not username:
            raise ValueError('username not found')
        res = lib.getJSON(
            'https://auth{:d}.tsinghua.edu.cn/cgi-bin/srun_portal'.format(ipv),
            {
                'action': 'logout',
                'username': username,
                'ac_id': '1',
                'ip': '',
                'double_stack': '1',
            },
            None,
        )
        return res
    return logout


def auth_checklogin(ipv):
    def checklogin():
        req = request.Request(
                'https://auth{:d}.tsinghua.edu.cn/ac_detect.php?ac_id=1'
                .format(ipv)
        )
        res = request.urlopen(req, timeout=5)
        assert 200 == res.getcode()
        url = res.geturl()
        username = parse.parse_qs(parse.urlparse(url).query).get('username')
        if not username:
            return {}
        else:
            return {
                'username': username[0],
            }
    return checklogin


def net_login(username, password):
    res = lib.get(
            'https://net.tsinghua.edu.cn/do_login.php',
            {
                'action': 'login',
                'username': username,
                'password': '{MD5_HEX}' + hashlib.md5(password).hexdigest(),
                'ac_id': '1',
            },
            None,
            'raw'
    )
    return {
        'msg': res,
    }


def net_logout():
    res = lib.get(
        'https://net.tsinghua.edu.cn/do_login.php',
        {'action': 'logout'},
        None,
        'raw'
    )
    return {
        'msg': res,
    }


def net_checklogin():
    return subdomain_info('net')()


def auth4():
    pass
auth4.login = auth_login(4)
auth4.logout = auth_logout(4)
auth4.checklogin = auth_checklogin(4)


def auth6():
    pass
auth6.login = auth_login(6)
auth6.logout = auth_logout(6)
auth6.checklogin = auth_checklogin(6)


def net():
    pass
net.login = net_login
net.logout = net_logout
net.checklogin = net_checklogin


if __name__ == '__main__':
    print(net.checklogin())
