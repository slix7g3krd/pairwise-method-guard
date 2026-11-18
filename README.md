# pairwise-method-guard

网关支持 `X-HTTP-Method-Override` 后，方法混淆就能绕过路由鉴权：GET 请求带头覆盖成 DELETE；覆盖头只在校验层生效，后端仍按原方法；大小写和空白没有归一；重复覆盖头取最后一个；代理转发时保留覆盖头；覆盖成 TRACE 能回显请求；路由按覆盖前方法匹配，鉴权按覆盖后；覆盖头允许任意值；CSRF 只校验 POST，覆盖后变 PUT；日志记录原方法，审计失真。security/method_guard.py 是核心，tests/test_method_guard.py 15个红。要修的是：覆盖仅限 POST；覆盖后重新鉴权；值归一；重复头拒绝；代理剥离；危险方法拒绝；路由与鉴权同源；方法白名单；CSRF 覆盖后仍校验；日志记录最终方法。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
