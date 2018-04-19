# -*- coding: UTF-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools
import hashlib

from . import lib
from six.moves.urllib import parse, request


class NotLoginError(Exception):
    pass


def _subdomain_info(subdomain):
    line = lib.get('https://{:s}.tsinghua.edu.cn/rad_user_info.php'
                   .format(subdomain), {}, None, 'raw')
    line = line.strip()
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


def _auth_login(ipv, username, password, net=False):
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


def _auth_logout(ipv):
    username = _auth_checklogin(ipv).get('username')
    if not username:
        raise NotLoginError('username not found')
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


def _auth_checklogin(ipv):
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


def _net_login(username, password):
    res = lib.get(
            'https://net.tsinghua.edu.cn/do_login.php',
            {
                'action': 'login',
                'username': username,
                'password': '{MD5_HEX}' + hashlib.md5(
                            password.encode('latin1')).hexdigest(),
                'ac_id': '1',
            },
            None,
            'raw'
    )
    return {
        'msg': res,
    }


def _net_logout():
    res = lib.get(
        'https://net.tsinghua.edu.cn/do_login.php',
        {'action': 'logout'},
        None,
        'raw'
    )
    return {
        'msg': res,
    }


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


if __name__ == '__main__':
    print(net.checklogin())
