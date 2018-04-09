from __future__ import print_function

import pprint
import tunet


username = 'username'
password = 'password'

if __name__ == '__main__':
    pprint.pprint(tunet.auth4.checklogin())
    pprint.pprint(tunet.auth4.login(username, password))
    pprint.pprint(tunet.net.checklogin())
