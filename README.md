# tunet-python

TUNet 2018 认证协议的纯 python 实现，含 auth4 / auth6 / net 认证。适用于服务器在无人交互时自动认证。

## API
API 共 3 * 3 项功能，对于 `https://{auth4,auth6,net}.tsinghua.edu.cn/` 分别有 login、logout、checklogin 三项功能。

用法示例：

```py
>>> import tunet
>>> print(tunet.auth4.login(username, password))
>>> print(tunet.net.checklogin())
```

在需要认证的网络环境下，可以用 `tunet.auth4.login(username, password, net=True)` 同时完成认证和登录，相当于在 auth4 网页端勾选“访问校外网络”。

行为定义：

|                  | 无需认证时   | 需认证但未认证时 | 已认证时 |
| :--------------- | :----------- | :--------------- | :------- |
| auth4.login      | 即时返回     | 即时返回         | 即时返回 |
| auth4.logout     | 即时异常退出 | 即时异常退出     | 即时返回 |
| auth4.checklogin | 即时返回     | 即时返回         | 即时返回 |
| auth6.login      | 即时返回     | 即时返回         | 即时返回 |
| auth6.logout     | 即时异常退出 | 即时异常退出     | 即时返回 |
| auth6.checklogin | 即时返回     | 即时返回         | 即时返回 |
| net.login        | 即时返回     | 超时异常退出     | 即时返回 |
| net.logout       | 即时返回     | 超时异常退出     | 即时返回 |
| net.checklogin   | 即时返回     | 超时异常退出     | 即时返回 |

特殊地，

 - 如果使用的是无线网络且没有登录 net，则无法访问 auth4、auth6，此时 auth4 和 auth6 的三项功能都会超时异常退出；
 - 如果无 IPv6 网络环境，则无法访问 auth6，此时 auth6 的三项功能都会即时异常退出。

API 总是提供原生的结果，如果不希望异常退出，或需要更友好的提示语，可自行包装一层。

## 命令行
提供简单的命令行包装，用法示例：

```sh
$ python cli.py auth4 checklogin
$ cat password.txt | python cli.py auth4 login -u username
$ python cli.py net checklogin
```

进程返回 0 的语义约定：

|                  | 进程返回 0 的情况      | 进程返回非 0 的情况  |
| :--------------- | :--------------------- | :------------------- |
| auth4 login      | 成功登陆，或此前已登录 | 连接错误或帐号错误   |
| auth4 logout     | 成功登出，或此前已登出 | 连接错误             |
| auth4 checklogin | 确认处于登录状态       | 连接错误或非登录状态 |
| auth6 login      | 成功登陆，或此前已登录 | 连接错误或帐号错误   |
| auth6 logout     | 成功登出，或此前已登出 | 连接错误             |
| auth6 checklogin | 确认处于登录状态       | 连接错误或非登录状态 |
| net login        | 成功登陆，或此前已登录 | 连接错误或帐号错误   |
| net logout       | 成功登出，或此前已登出 | 连接错误             |
| net checklogin   | 确认处于登录状态       | 连接错误或非登录状态 |

login 的密码输入方式：如果标准输入流是 tty，则使用 getpass 读取，无回显；否则，从标准输入读取一行。
