# tunet-python

TUNet 2018 认证协议的纯 python 实现，含 auth4 / auth6 / net 认证。适用于服务器在无人交互时自动认证。

# API
API 共 3 * 3 项功能，对于 `https://{auth4,auth6,net}.tsinghua.edu.cn/` 分别有 login、logout、checklogin 三项功能。

用法示例：

```py
import tunet
print(tunet.auth4.login(username, password))
print(tunet.net.checklogin())
```

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
| net.logout       | 即时异常退出 | 超时异常退出     | 即时返回 |
| net.checklogin   | 即时返回     | 超时异常退出     | 即时返回 |

特殊地，

 - 如果使用的是无线网络且没有登录 net，则无法访问 auth4、auth6，此时 auth4 和 auth6 的三项功能都会超时异常退出；
 - 如果无 IPv6 网络环境，则无法访问 auth6，此时 auth6 的三项功能都会即时异常退出。

API 总是提供原生的结果，如果不希望异常退出，或需要更友好的提示语，可自行包装一层。
