# 把应用登录证明绑定到 TLS：EKM 与 Finished 的实验结论

环境：pyOpenSSL 26.4.0，链接 OpenSSL 4.0.3（`.venv`）；另用标准库 `ssl`（OpenSSL 3.5.3）
做交叉验证。全部连接走内存 BIO（`Connection(ctx, None)` + `bio_read/bio_write`），
不监听端口，因此在禁止本地端口绑定的沙箱里可复现。

代码：
- `make_certs.py`：测试 PKI（CA、server、client-a、client-b）。
- `lab.py`：内存 BIO 泵、上下文工厂、快照采集。
- `run_experiments.py`：全部场景与断言，输出见 `results.txt`。
- `recommended_interface.py`：生产风格的分层接口参考。

复现：
```
.venv/bin/python experiments/ekm-study/make_certs.py
.venv/bin/python experiments/ekm-study/run_experiments.py
```

---

## 1. 一句话结论：绑定的是“连接”，不是“证书身份”

`export_keying_material()`（RFC 5705 / RFC 8446 的 Exporter，EKM）和
`get_finished()/get_peer_finished()` 的输入都是**本次握手协商出的密钥与握手转录**，
因此它们证明的是：

> 证明持有方拥有“当前这条 TLS 关联（association）”的导出密钥。

它们**不**以证书公钥为输入。实验中两条用同一张服务器证书、同一组 Context 建立的新
连接，EKM、Finished、client_random 全部不同，而证书指纹与 `tls-server-end-point`
（证书 SPKI 的哈希）完全相同。证书身份属于另一个独立维度。

| 材料 | 实际能证明什么 | 是否长期身份 | 能否原样外发 |
|---|---|---|---|
| EKM（导出密钥） | 持有本连接导出密钥；同一连接两端算出相同值 | 否，每连接/每握手变化 | 否，应只外发 HMAC 标签 |
| `get_finished` / `get_peer_finished` | 某次握手的 Finished verify_data（转录完整性） | 否 | 否，属敏感握手段 |
| 证书 / SPKI 哈希（`tls-server-end-point`） | 经认证的证书身份 | 是，证书轮换前稳定 | 可（哈希/指纹可记录比对） |

---

## 2. 新连接：标签、无 context、空 context 的精确含义

### 2.1 label（标签）
- 是一个“域分离”字符串。同一连接上不同 label 派生出**相互独立**的输出
  （实验：`com.example.login-proof` 与 `com.example.something-else` 的 EKM 不同）。
- 应使用**应用私有、固定、带版本号**的 label（如
  `com.example.login-channel-binding-v1`）。不要借用别的协议注册过的
  `EXPORTER-*` 名称，否则会与该协议的密钥域混淆。
- label 不决定身份，只决定“这条派生材料用于哪个用途”。

### 2.2 context 未提供（`None`）与空 context（`b""`）——两版本语义不同
pyOpenSSL 的映射（见 `SSL.py` 中 `export_keying_material`）：
- `context=None` → OpenSSL `use_context=0`（**不带** context）。
- `context=b""` → `use_context=1`，context 长度为 0（**显式带一个零长** context）。

实测：
- **TLS 1.2：`None` 与 `b""` 结果不同。** RFC 5705 用 `use_context` 标志位区分两种
  PRF 输入，零长 context 是一种独立取值，不能混用。
- **TLS 1.3：`None` 与 `b""` 结果相同。** RFC 8446 总是对 context 做长度前缀
  （`HkdfLabel.context_length`），“没有 context”就等价于零长 context。

含义：跨 1.2/1.3 的代码必须**显式、统一地选择其中一种**，不要在 1.2 上依赖“空与无
相等”的假设。需要把应用数据（租户、nonce、目标标识）绑进材料时，传**非空** context。

### 2.3 长度参数也是派生输入（易踩坑）
- TLS 1.2：PRF 是一条扩展流，16 字节导出是 32/64 字节导出的前缀（实测成立）。
- TLS 1.3：长度 `L` 被编码进 HKDF-Expand 的 label，**不同长度的输出互不为前缀**
  （实测 16B ≠ 32B 的前 16 字节）。因此长度也要在协议里固定（建议 32 字节）。

### 2.4 决定性与独立性
- 同连接、同 label/context/长度重复调用，结果稳定（确定性）。
- EKM ≠ master key，EKM ≠ 任一 Finished 值；它是独立的派生密钥。
- 非空 context 不同（`CTX_A` vs `CTX_B`）→ 输出不同，可用来把证明限定到具体
  租户/会话/挑战。

---

## 3. 会话恢复：恢复了什么，绑定材料还成立吗

判据用底层 `SSL_session_reused()`（pyOpenSSL 无公开包装）。两套机制都实测
`resumed=1`。

### 3.1 TLS 1.2
- 恢复复用同一个 master secret（实测两连接 `master_key` 哈希相同）。
- 但 client_random、两端 Finished、所有 EKM 取值**全部变化**。
- 结论：即便会话被复用，EKM/Finished 仍绑定到**这条新连接**，不会从上一条连接
  延续。`tls-unique`（RFC 5929，取客户端 Finished verify_data）在恢复场景下的
  安全性被 RFC 明确弱化，不建议作为首选。

### 3.2 TLS 1.3
- 恢复走 PSK（pre_shared_key），每条连接仍派生全新的流量密钥与 exporter 主密钥；
  实测 EKM、Finished、client_random 全部变化。
- 实现注意（本环境两个坑，均已在 `lab.py` 解决）：
  1. **票据处理时机**：内存 BIO 下，客户端要等到一次记录层操作（应用数据往返）
     才会把 post-handshake 的 NewSessionTicket 并入可恢复会话；在此之前
     `get_session()` 里票据字段为空，下一个 ClientHello 不带 `pre_shared_key`。
  2. **票据密钥按 SSL_CTX**：1.3 票据用服务端 `SSL_CTX` 的密钥加密，换一个全新
     服务端 Context 无法兑现，必须用同一 Context 接受恢复。
- OpenSSL 版本差异：3.x 在握手后擦除 TLS 1.3 master secret（`master_key()` 抛错），
  4.0 又可读出恢复主密钥；但无论哪种，**EKM 都按连接轮换**，这才是绑定依赖的性质。

### 3.3 恢复对“身份”的影响
证书指纹 / `tls-server-end-point` 在原连接与恢复连接间保持不变。即：
- 想证明“还是那台持证服务器” → 用证书/SPKI 身份（稳定）。
- 想证明“就是当前这条连接” → 用 EKM（每连接唯一）。二者不可互相替代。

---

## 4. 身份变化过程：PHA 与重协商里的错误假设

### 4.1 TLS 1.3 握手后认证（PHA，Post-Handshake Authentication）
这是 1.3 唯一支持的“连接中途加客户端证书”的机制。**pyOpenSSL 无公开 API**，
实验通过私有 cffi 绑定完成（`SSL_CTX_set_post_handshake_auth`、
`SSL_verify_client_post_handshake`、`SSL_VERIFY_POST_HANDSHAKE`），属可移植性边界。

在同一条连接上先无证书握手，再连续两次 PHA（client-a → client-b），实测：

- **EKM 全程不变**（base = PHA#1 = PHA#2）。PHA 不重新密钥协商。
- **服务器侧 Finished（`get_peer_finished`）不变**：服务器只在初始握手发过一次
  Finished，PHA 不带新的服务器 Finished。
- **客户端 `get_finished()` 每次 PHA 都变**：每条 post-handshake Authentication
  自带一个新的客户端 Finished，访问器返回“最近一次”的值。这是最容易做错的假设——
  不能把 `get_finished()` 当成整个连接生命周期恒定的句柄。
- 服务器看到的客户端证书指纹随 PHA 切换（client-a → client-b 实测不同）。

关键推论：
> 基础 EKM 与初始 Finished **不包含** PHA 之后才出现的客户端证书身份。

RFC 9266 定义了用“截至客户端 Certificate 消息的转录哈希”作为 context 的
`tls-exporter`，可以把 PHA 身份绑进导出材料；但 **pyOpenSSL 不暴露握手转录**，
无法在本库内构造该 context。可行替代：用**应用提供的 context**（把本次 PHA 的
证书指纹/序号放进 EKM context），或在应用层对 PHA 证书另做签名证明。

### 4.2 TLS 1.2 重协商（Renegotiation，遗留路径）
OpenSSL 3.x/4.x 默认 `OP_NO_RENEGOTIATION`，实验需显式关闭该选项。

- 服务端发起的重协商会跑一次**完整的新握手**：实测 EKM、Finished、client_random
  全部改变（与 PHA 正相反，重协商确实重新生成密钥）。
- 边界（OpenSSL 4.0 实测）：
  - **客户端发起的重协商被直接拒绝**（`no renegotiation`）。
  - 初始握手未请求客户端证书时，服务端重协商里不会再注入新的
    CertificateRequest；已存在的客户端证书只是被“延续”，不会在重协商中重新认证或
    更换（实测切换到 client-b 后服务器仍记录 client-a 指纹）。
  - TLS 1.3 调用 `renegotiate()` 直接报 `wrong ssl version`（协议层面无重协商）。
- 因此在现代栈上，**不要依赖重协商来做身份变更**；1.3 用 PHA，1.2 重协商只当作
  会重新密钥化的遗留能力对待。

---

## 5. 哪些值能给验证方，哪些不能当长期身份

### 5.1 可以给验证方的
- **由 EKM 作密钥算出的 HMAC 标签**（针对服务端下发的随机挑战 + 应用 context）。
  原始 EKM 永不过线；验证方（服务端）用自己那份相同 EKM 重算并 `compare_digest`。
- **证书/SPKI 指纹**（如 `tls-server-end-point`）：可记录、可比对、可审计，是稳定
  身份句柄。
- 协议版本、密码套件、是否恢复等元数据。

### 5.2 不能直接给、或不能当身份的
- **原始 EKM、master key、Finished verify_data**：都是每连接/每握手的敏感密钥材料。
  外泄等于让别人能在该连接有效期内冒充通道；它们随连接轮换，**不能充当长期身份**，
  也不能入库当用户主键。
- **`get_finished()` 在 1.3 PHA 下会变**，不能当连接的恒定标识；`tls-unique` 在
  TLS 1.3 无定义、在 1.2 恢复场景弱化，不要作为跨版本统一方案。
- 会话票据/PSK、session 对象本身也是短期、可轮换的，不是身份。

### 5.3 推荐的标准化通道绑定（若需要跨实现互操作）
- TLS 1.3 优先 **RFC 9266 `tls-exporter`**：label `EXPORTER-tls-exporter`、长度 32、
  基础场景零长 context；带客户端认证时用其定义的转录 context（本库拿不到转录，见 4.1）。
- 仅服务端身份、需要跨恢复稳定时，可用 RFC 5929 `tls-server-end-point`（证书 SPKI 哈希）。

---

## 6. 接口建议：通道持有证明 与 用户授权 分层

核心原则：**两个独立的信任决定，在应用层组合，不要合并。**

1. 通道持有（channel possession）
   - 服务端生成一次性随机挑战 `challenge`，并约定 `context = 租户/会话/目标`。
   - 客户端 `proof = HMAC(EKM(label, 32, context), challenge)`，只回传 proof。
   - 服务端用自己的 EKM 重算并恒定时间比对；其他连接的 EKM 不同，无法伪造
     （实验 `proof_suite` 已验证并行连接的标签不通过）。
2. 用户授权（user authorization）
   - 用独立的应用令牌（OIDC/JWT 等）解析出 `user_id`，与 TLS 完全解耦。
   - 对应标准做法可参考 RFC 8705 的 `tls_client_certificate_bound_access_tokens`
     （把访问令牌绑定到客户端证书），但要注意它绑的是**证书**，不是 EKM。
3. 组合与审计
   - 登录结果同时记录：`user_id`（授权层）、`peer_spki_fp`（稳定证书身份）、
     本次 proof 校验通过（当前连接持有）。
   - 这样可区分三类故障：连接不持有（proof 失败）、用户未授权（令牌失败）、
     证书身份不符（SPKI 不匹配）。

参考实现见 `recommended_interface.py` 的 `ChannelBinding` 与 `verify_login()`，
已在内存 BIO 的 TLS 1.3 连接上端到端跑通（含伪造标签拒绝、坏令牌拒绝）。

---

## 7. 实现支持边界汇总（本环境实测）

| 能力 | pyOpenSSL 公开 API | 本实验如何实现 / 边界 |
|---|---|---|
| EKM 导出（1.2/1.3） | 是，`Connection.export_keying_material` | 直接可用 |
| Finished 读取 | 是，`get_finished/get_peer_finished` | 1.3 PHA 下客户端值会被覆盖 |
| TLS 1.2 会话恢复 | 是，`get_session/set_session` | 服务端需 `set_session_id` |
| TLS 1.3 票据恢复 | 部分 | 需记录层 I/O 触发票据处理 + 同 SSL_CTX；无公开 `session_reused`，用底层 |
| TLS 1.3 PHA | **否** | 仅能经 `OpenSSL._util` 私有绑定；无转录 API，做不了 RFC9266 context |
| TLS 1.2 重协商 | 是，`renegotiate()` | 默认禁用需开选项；客户端发起被 4.0 拒绝；不能借此换客户端证书 |
| RFC 9266 转录 context | **否** | 无握手转录访问；用应用 context 替代 |
| 本地 socket 回环 | 环境限制 | 沙箱禁止端口绑定，故全部用内存 BIO（标准库 ssl 交叉验证同结论） |
