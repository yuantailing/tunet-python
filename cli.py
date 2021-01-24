# -*- coding: UTF-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import getpass
import sys
import tunet

if sys.version_info[0] == 2:
    import urllib2
    URLError = urllib2.URLError
else:
    import urllib.error
    URLError = urllib.error.URLError


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
                        description='TUNet Command-Line Interface')
    parser.add_argument('target',
                        help='Select a target: auth4 / auth6 / net')
    parser.add_argument('action',
                        help='Select an action: login / logout / checklogin')
    parser.add_argument('-u', '--user', '--username',
                        help='username to login', required=False)
    parser.add_argument('-n', '--net', action='store_true',
                        help='access to the Internet', required=False)
    args = parser.parse_args()

    def error(s):
        print(s)
        exit(1)

    if args.target not in ('auth4', 'auth6', 'net'):
        error('tunet: no such target')
    if args.action not in ('login', 'logout', 'checklogin'):
        error('tunet: no such action')
    target = getattr(tunet, args.target)
    action = getattr(target, args.action)
    if args.action == 'login':
        if not args.user:
            error('login: username required')
        if sys.stdin.isatty():
            password = getpass.getpass()
        else:
            password = sys.stdin.readline().rstrip('\n')
        try:
            if args.target == 'net':
                res = action(args.user, password)
            else:
                res = action(args.user, password, bool(args.net))
        except URLError as e:
            error('URLError: {:s}'.format(e))
    else:
        try:
            res = action()
        except URLError as e:
            error('URLError: {:s}'.format(e))

    if args.target == 'net':
        if args.action == 'checklogin':
            if not res.get('username'):
                print('not login')
                exit(1)
            else:
                print('Username:', res['username'])
                print('Time online:', res['time_query'] - res['time_login'])
                print('Session traffic incoming:', res['session_incoming'])
                print('Session traffic outgoing:', res['session_outgoing'])
                print('Cumulative traffic:', res['cumulative_incoming'])
                print('Cumulative online time', res['cumulative_time'])
                print('IPv4 address:', res['ipv4_address'])
                print('Balance:', res['balance'])
                exit(0)
        else:
            print('message:', res['msg'])
            if 'is successful' in res['msg'] or \
                    'has been online' in res['msg'] or \
                    'are not online' in res['msg']:
                exit(0)
            else:
                exit(1)
    else:
        if args.action == 'checklogin':
            if not res.get('username'):
                print('not login')
                exit(1)
            else:
                print('username:', res['username'])
                exit(0)
        else:
            print('return:', res.get('error'))
            print('result:', res.get('res'))
            print('message:', res.get('error_msg'))
            if res.get('error') == 'ok' or \
                    res.get('error') == 'ip_already_online_error' or \
                    (args.action == 'logout' and
                        res.get('error') == 'login_error'):
                exit(0)
            else:
                exit(1)
