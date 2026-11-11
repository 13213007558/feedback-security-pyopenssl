# OCSP Stapling 强制策略：覆盖表与库接口边界

客户端策略：**只有握手完成且本次握手获得过被验证回调接受的非空 stapled
OCSP 响应，业务才可将连接视为已验证**。实现见
`secure_client_config.py`（`StaplingClientContext` + `OCSPStaplingPolicy`），
回归见 `test_ocsp_stapling_policy.py`（内存 BIO，预制 DER 响应，受控验证回调）。

运行：`.venv/bin/python -m pytest ocsp-stapling/`

## 覆盖矩阵（实测记录，非推断）

| # | 场景 | TLS | 客户端回调是否触发 | 握手结果 | `is_verified()` |
|---|------|-----|--------------------|----------|------------------|
| 1 | 请求 + 服务端 staple GOOD 响应，链可信 | 1.2 / 1.3 | 是（非空 DER） | 成功 | **True** |
| 2 | 客户端未调用 `request_ocsp()` | 1.2 / 1.3 | **否（0 次）** | **成功** | False |
| 3 | 请求了但服务端无 OCSP 配置 | 1.2 / 1.3 | 是（`b""`） | 失败（策略拒绝） | False |
| 4 | 服务端回调返回空响应 `b""` | 1.2 / 1.3 | 是（`b""`） | 失败（策略拒绝） | False |
| 5 | 回调接受（验证通过） | 1.2 / 1.3 | 是（非空 DER） | 成功 | True |
| 6 | 回调拒绝（REVOKED 响应） | 1.2 / 1.3 | 是（非空 DER） | 失败 | False |
| 7 | 验证回调抛异常 | 1.2 / 1.3 | 是 | 异常冒泡给调用方 | False |
| 8 | 证书链验证失败（信任错误 CA）但 staple 有效响应 | 1.2 / 1.3 | **否（0 次，OpenSSL 先中止）** | 失败 | False |
| 9 | TLS 1.2 会话恢复 | 1.2 | **否（0 次）** | **成功** | False |
| 10 | TLS 1.3 会话恢复（PSK） | 1.3 | 是（`b""`） | 失败（策略拒绝空信号） | False |

关键结论：

- 场景 2 与 9 证明"普通握手成功"不能推断已获得新的撤销证据——
  回调可能根本没发生。只有策略层的状态检查（`is_verified()`）能兜底。
- 场景 10 证明"回调发生了"也不够——TLS 1.3 恢复时回调以 `b""` 触发，
  必须要求非空负载且被验证回调接受。
- 场景 8 证明链验证失败时 OpenSSL 在 OCSP 客户端回调之前中止握手，
  链失败与 stapling 证据不会同时出现，不存在"撤销证据好但链坏"的歧义窗口。

## 受控验证回调代替了什么

测试中 `make_validator` 解析预制 DER 并检查：响应状态为 SUCCESSFUL、
证书状态为 GOOD、序列号匹配、`this_update`/`next_update` 新鲜度窗口、
响应签名可被测试 CA 验证。生产回调还须（详见
`secure_client_config.py` 模块 docstring）：

- 核对 `certID` 的 issuer 名称/密钥哈希与真实签发者、哈希算法一致性；
- 验证响应者身份：CA 本身，或链到 CA 且带 `id-kp-OCSPSigning` EKU 的
  委派响应者证书；
- 校验 nonce（若发送）；pyOpenSSL 不会自动加 nonce。

## pyOpenSSL 接口无法保证的情形

- **TLS 1.2 恢复无回调**：库不暴露任何"恢复发生了但无 stapling"的钩子；
  应用必须在握手后主动检查策略状态，不能依赖回调副作用。
- **无 `SSL_get_verify_result` 封装**：链验证结果只能以
  `VERIFY_PEER` 中止握手的方式体现，无法事后查询验证错误码。
- **回调只给原始 DER**：解析与全部语义校验（certID、签名者授权、
  新鲜度、nonce）都在应用侧；库不做任何 OCSP 内容验证。
- **不支持 must-staple / `status_request_v2`**：pyOpenSSL 未暴露
  TLS Feature 扩展或多证书 stapling，无法表达"证书要求必须 staple"。
- **主机名校验不在库内**：需应用自行完成（如 `service_identity`），
  本策略不覆盖。
- **策略状态是应用侧构造**：`is_verified()` 的正确性依赖每连接一个
  policy 实例、握手后设置 `handshake_completed`；库不会强制此纪律。
