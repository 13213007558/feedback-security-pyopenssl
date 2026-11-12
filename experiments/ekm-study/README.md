# EKM / Finished 绑定实验

用内存 BIO（无端口、无 socket）在 pyOpenSSL 上对比 TLS 1.2 与 TLS 1.3 的
Exporter Keying Material（EKM）与 Finished 数据，覆盖新连接、会话恢复、
TLS 1.3 握手后认证（PHA）与 TLS 1.2 重协商。

## 文件
- `make_certs.py`：生成测试 PKI（CA、server、client-a、client-b）。
- `lab.py`：内存 BIO 泵、上下文工厂、快照与通道绑定工具。
- `run_experiments.py`：全部场景与断言；运行产出 `results.txt`。
- `recommended_interface.py`：通道持有证明与用户授权分层的参考接口。
- `FINDINGS.zh.md`：完整结论与边界（先读这个）。
- `results.txt`：最近一次运行的完整转录。

## 复现
```
.venv/bin/python experiments/ekm-study/make_certs.py
.venv/bin/python experiments/ekm-study/run_experiments.py
```

## 环境
- pyOpenSSL 26.4.0 + OpenSSL 4.0.3（venv 内）。
- 标准库 `ssl`（OpenSSL 3.5.3）用于会话恢复的交叉验证。
- 沙箱禁止本地端口绑定，因此全程使用 `Connection(ctx, None)` 内存 BIO。
