# tunet-python
TUNet 2018 的纯 python 实现，含 auth 认证协议

# API
API 共 3 * 3 项功能，对于 `https://{auth4,auth6,net}.tsinghua.edu.cn` 分别有 login、logout、checklogin 三项功能。

用法示例：

```py
import tunet
print(tunet.auth4.login(username, password))
print(tunet.net.checklogin())
```

行为定义：

|                  | 无需认证时   | 未认证时     | 已认证时 | 无线网络未连net时 | 无IPv6时     |
| :--------------- | :----------- | :----------- | :------- | :---------------- | :----------- |
| auth4.login      | 即时返回     | 即时返回     | 即时返回 | 超时异常退出      | （无影响）   |
| auth4.logout     | 即时异常退出 | 即时异常退出 | 即时返回 | 超时异常退出      | （无影响）   |
| auth4.checklogin | 即时返回     | 即时返回     | 即时返回 | 超时异常退出      | （无影响）   |
| auth6.login      | 即时返回     | 即时返回     | 即时返回 | 即时异常退出      | 即时异常退出 |
| auth6.logout     | 即时异常退出 | 即时异常退出 | 即时返回 | 即时异常退出      | 即时异常退出 |
| auth6.checklogin | 即时返回     | 即时返回     | 即时返回 | 即时异常退出      | 即时异常退出 |
| net.login        | 即时返回     | 超时异常退出 | 即时返回 | 即时返回          | （无影响）   |
| net.logout       | 即时异常退出 | 超时异常退出 | 即时返回 | 即时返回          | （无影响）   |
| net.checklogin   | 即时返回     | 超时异常退出 | 即时返回 | 即时返回          | （无影响）   |

API 总是提供原生的结果，如果不希望异常退出，或需要更友好的提示语，可自行包装一层 try。
