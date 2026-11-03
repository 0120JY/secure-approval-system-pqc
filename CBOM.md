# 密码物料清单（Crypto Bill of Materials, CBOM）

- **项目**：密码敏捷审批与安全归档框架（`secure-approval-system-pqc`）
- **文档版本**：**v2**（2026-10-31 增量修订）；v1（2026-10-26）保留为“迁移前基线”
- **代码版本**：当前工作区，基于 2026-10-31 静态扫描与 72 项测试结果
- **扫描范围**：`main.py`、`self_check.py`、`run_tests.py`、`lab/`、`tasks/`、`tests/`、`requirements.txt`
- **排除范围**：`.venv/`、`__pycache__/`、`runtime/`（运行时产物）、`samples/`（虚构数据）
- **方法**：源码检索（SM2/SM3/SM4、ML-DSA/pqcrypto、hashlib、hmac、secrets、cryptography、gmssl、base64 等）+ 逐文件人工核对调用链与业务语义 + 测试证据映射
- **结论（v2）**：签名链已迁移为 **ML-DSA-65 默认签名 + SM2 历史只读兼容**；SM3、SM4-GCM、PBKDF2、CSPRNG 仍不需要 PQC 替换。非对称侧不再有未迁移的生产路径，剩余风险集中在**密钥保护**（明文 SQLite）与**第三方实现**（pqcrypto 非 FIPS 认证、gmssl 非恒定时间）。
- **配套文档**：[`README.md`](README.md)（使用与配置）、[`SECURITY_REPORT.md`](SECURITY_REPORT.md)（威胁建模、风险矩阵与测试证据映射）

---

## 1. 执行摘要

| 维度 | v2 结果 | 相对 v1 的变化 |
|---|---|---|
| 非对称签名 | **ML-DSA-65（默认，FIPS 204）** + **SM2（历史只读验签）** | 新增 ML-DSA 并切换默认；SM2 退出签发路径 |
| 对称算法 | SM4-128-GCM（认证加密） | 无变化 |
| 哈希算法 | SM3-256 | 无变化 |
| 口令派生 | PBKDF2-HMAC-SHA256（260,000 轮） | 无变化 |
| 随机数 | Python `secrets`（OS CSPRNG） | 无变化 |
| 密钥交换 / KEM | **不存在** | 无变化 |
| RSA / ECDSA / ECDH / DH / AES / ChaCha20 | **不存在** | 无变化 |
| TLS / CA / 证书链 | **不存在** | 无变化 |
| 主要依赖 | `gmssl 3.2.2`（SM2）、`cryptography 46.0.3`（SM3、SM4-GCM）、`pqcrypto 1.0.0`（ML-DSA）、Python 标准库；传递依赖 `pycryptodomex`、`cffi`、`pycparser` 已锁定 | 新增 `pqcrypto` |
| PQC 迁移状态 | **签名链已完成**；密钥保护、协议升级、SM2 退役未完成 | v1 为“待迁移” |
| PQC 迁移总工作量 | 剩余工作为**密钥保护（HSM/KMS）与协议升级**，非算法替换 | 从“换算法”转为“运维与生命周期治理” |

**一句话结论**：这是一个“SM4-GCM 保护数据、SM3 保证完整性、**ML-DSA-65 保证审批不可否认**（SM2 仅供历史数据只读验签）”的结构。量子威胁原先只命中 SM2；v2 已把签名算法、密钥格式、签名长度、信任登记表统一做成算法敏捷的，并用 72 项测试锁定行为。**算法替换已完成，真正的剩余风险在私钥保护和第三方密码实现的信任上。**

### 1.1 v1 → v2 修订摘要

| 变更项 | v1（迁移前） | v2（当前） | 主要证据 |
|---|---|---|---|
| 默认签名算法 | SM2 | **ML-DSA-65** | `lab/config.py:10` |
| 验签默认算法 | 无此概念 | `LEGACY_VERIFY_ALGORITHM = "SM2"`（无提示时回退） | `lab/config.py:11,38-40` |
| 公钥/签名编码 | 128 hex 定长 | **严格 canonical Base64**；Hex 逐行只读 | `lab/crypto_encoding.py:20-30` |
| 算法分派 | 业务直接调 `gmssl` | `Signer` 契约 + `SIGNERS` 注册表 | `lab/signers.py:61-104,261-274` |
| 公钥登记表 | `public_keys(key_id, owner_id, public_key, active)` | 增加 `alg`、`encoding` | `lab/store.py:18-22,56-68` |
| 审批记录 | 仅 `signature` | 增加 `sig_alg`、`sig_encoding` | `lab/store.py:28-34` |
| 密钥库 | `owner_id UNIQUE`，只能持一把钥匙 | 去掉 UNIQUE，同一主体可共存 SM2/ML-DSA | `lab/crypto.py:64-80` |
| 混合签名 | 建议作为过渡方案 | **未采用**：直接替换 + 旧数据只读兼容 | 见 4.1 |
| 测试规模 | 50 项 | **72 项**（50 既有 + 13 敏捷性 + 9 ML-DSA） | `run_tests.py`、`tests/test_ml_dsa.py` |

---

## 2. 密码资产总览

### 2.1 算法族分布

| 类别 | 算法 | 出现位置 | 是否受 Shor 算法威胁 | PQC 结论 |
|---|---|---|---|---|
| 非对称签名（默认） | **ML-DSA-65**（FIPS 204，ML-DSA-44/87 可选） | `lab/signers.py:176-252`、`lab/config.py:10-13` | 否（基于格） | **已迁移** |
| 非对称签名（兼容） | SM2（SM3-with-SM2） | `lab/signers.py:106-173`；仅历史数据验签 | **是** | **已迁移**：不再签发，仅只读验签 |
| 哈希 | SM3-256 | `lab/crypto.py:28-33`、`tasks/*` | 否（仅 Grover 降级） | 无需迁移 |
| 对称 AEAD | SM4-128-GCM | `lab/crypto.py:150-203` | 否（仅 Grover 降级） | 无需迁移 |
| 口令 KDF | PBKDF2-HMAC-SHA256 | `lab/auth.py:24-26` | 否 | 无需迁移 |
| CSPRNG | `secrets` | `lab/auth.py`、`lab/crypto.py` | 否 | 无需迁移 |
| 编码 | 标准 Base64（RFC 4648） | `lab/crypto_encoding.py`、`tests/` | 否（非密码原语） | 无需迁移 |
| 第三方密码实现 | `gmssl 3.2.2`、`cryptography 46.0.3`、`pqcrypto 1.0.0`（传递依赖 `pycryptodomex`、`cffi`、`pycparser`） | `requirements.txt` | 否 | 供应链持续评估（见 5.1.9） |

### 2.2 关键调用链

```
学生提交
  tasks.workflow_tasks.submit_material
    -> calculate_file_sm3 (SM3)                    文件完整性
    -> sm3_hex(json_text(...))                    提交幂等指纹
    -> Crypto.seal("archive_service")              SM4-GCM 加密
       -> 每文档新 16B 密钥 + 12B nonce + AAD

辅导员审批
  Context.prepare_approval
    -> build_approval_manifest (10 字段规范化清单)
    -> Crypto.sign(actor_id, key_id, data)         审批签名
       -> get_signer(密钥记录的 alg)                默认 ML-DSA-65
       -> MLDSASigner.sign / SM2Signer.sign        算法内聚
  tasks.workflow_tasks.handle_approval
    -> verify_approval_signature
       -> Crypto.verify(..., alg=登记表 alg,
                           encoding=登记表 encoding) 先验签（不猜算法）
    -> 幂等去重（SM3 清单指纹）
    -> Crypto.open("review_service")               SM4-GCM 解密
    -> check_document_binding (重算 SM3)            内容/版本绑定
    -> add_approval + processed_requests + audit   同一事务

受控读取
  tasks.workflow_tasks.read_material
    -> authorize_action
    -> Crypto.open("query_service")                SM4-GCM 解密
    -> 重算 SM3 比对                                完整性
```

---

## 3. CBOM 主表

> 优先级定义：**高** = Shor 可破解、必须替换的非对称密码；**中** = 迁移时必须同步改造的算法标识/存储/测试资产；**低** = 仅测试行为、不绑定算法；**无需迁移** = 对称、哈希、随机数、编码。

| 涉及文件/行号 | 密码操作 | 算法（v2） | 依赖库 | 业务用途 | PQC迁移优先级 | v2 状态 |
|---|---|---|---|---|---|---|
| `lab/signers.py:44-47` | SM2 密钥对生成（私钥 d∈[1,n−2]，公钥 dG） | SM2（ECC，256-bit） | gmssl 3.2.2 | 历史 SM2 身份与兼容签名 | **高** | 只读兼容，不再签发 |
| `lab/signers.py:30-35` | SM2 曲线引擎构造（含公钥前导 `04` 修复） | SM2（ECC） | gmssl 3.2.2 | SM2 运算的底层适配 | **高** | 只读兼容 |
| `lab/signers.py:50-58` | 公钥曲线点合法性校验（y²=x³+ax+b mod p） | SM2（ECC） | gmssl 3.2.2 | 历史公钥登记校验 | **高** | 只读兼容 |
| `lab/signers.py:120-130` | SM2 签名（SM3-with-SM2，随机 k，输出 r\|\|s → Base64） | SM2 + SM3 | gmssl 3.2.2 | 历史签名生成（测试/兼容） | **高** | 只读兼容；生产不签发 |
| `lab/signers.py:132-145` | SM2 验签 + r/s 范围校验 | SM2 + SM3 | gmssl 3.2.2 | 历史审批签名验证 | **高** | 保留，可被调用 |
| `lab/signers.py:176-201` | ML-DSA 参数集与尺寸声明（44/65/87） | ML-DSA | pqcrypto 1.0.0 | 算法元数据与长度约束 | **高** | **已完成** |
| `lab/signers.py:203-208` | pqcrypto 延迟导入 | ML-DSA | pqcrypto 1.0.0 | 未安装依赖时返回 `CRYPTO_UNAVAILABLE` | **高** | **已完成** |
| `lab/signers.py:210-215` | ML-DSA 密钥对生成（pqcrypto `keygen`） | ML-DSA | pqcrypto 1.0.0 | 新审批身份密钥 | **高** | **已完成** |
| `lab/signers.py:217-223` | ML-DSA 签名（透传 FIPS 204 `context`） | ML-DSA | pqcrypto 1.0.0 | 审批决定不可否认签名 | **高** | **已完成** |
| `lab/signers.py:225-235` | ML-DSA 验签（`InvalidSignatureError` → False） | ML-DSA | pqcrypto 1.0.0 | 审批签名真实性验证 | **高** | **已完成** |
| `lab/signers.py:255-274` | 算法注册表与零参工厂 | 算法分派 | — | `SM2` / `ML-DSA-44/65/87` 解析 | **高** | **已完成** |
| `lab/crypto.py:133-148` | `Crypto.sign` / `Crypto.verify` 算法分派 | 多算法 | — | 业务层不感知具体算法 | **高** | **已完成** |
| `lab/crypto.py:36-117` | 私钥软件密钥库（SQLite 明文私钥；目录 0700/文件 0600） | 密钥存储（SM2 / ML-DSA 私钥） | sqlite3（stdlib） | 签名私钥生命周期管理 | **高** | **仍存在风险**（未迁 HSM/KMS） |
| `lab/crypto.py:111-117` | 私钥按 `owner_id` 绑定取用 | 密钥访问控制 | sqlite3（stdlib） | 防止跨账号/越权使用他人私钥 | **高** | 已保留 |
| `lab/crypto.py:92-109` | 初始化签名密钥并登记公钥 | SM2 / ML-DSA | gmssl / pqcrypto + sqlite3 | 建立签名信任锚（T017/T018） | **高** | **已完成**（按 `SIGNING_ALGORITHM`） |
| `lab/context.py:20-26` | 登记公钥到 `public_keys`（含 alg/encoding） | SM2 / ML-DSA | sqlite3 | 建立签名信任锚 | **高** | **已完成** |
| `lab/context.py:72-86` | 构造规范化审批清单并调用签名 | **ML-DSA-65（默认）** | pqcrypto 1.0.0 | 辅导员终端确认后签发审批凭证 | **高** | **已完成** |
| `tasks/access_tasks.py:69-90` | 身份绑定 + 可信密钥表 + 按登记算法验签 | ML-DSA / SM2 | pqcrypto / gmssl | 审批链信任校验（先验签后幂等） | **高** | **已完成** |
| `lab/store.py:18-22, 56-68` | `public_keys` 增加 `alg` / `encoding` 并平滑迁移 | 存储格式 | sqlite3（stdlib） | 信任锚登记算法与编码 | **中** | **已完成** |
| `lab/store.py:28-34, 56-68` | `approvals` 增加 `sig_alg` / `sig_encoding` 并平滑迁移 | 存储格式 | sqlite3（stdlib） | 审批凭证记录算法与编码 | **中** | **已完成** |
| `lab/crypto.py:64-80` | 密钥库去掉 `owner_id` UNIQUE（表重建迁移） | 密钥存储 | sqlite3（stdlib） | 同一主体可共存 SM2/ML-DSA 密钥 | **中** | **已完成** |
| `lab/crypto_encoding.py:20-30, 43-61` | canonical Base64 严格解码 + 旧 Hex 识别 | 编码（非密码） | base64（stdlib） | 变长公钥/签名统一编码 | **中** | **已完成** |
| `lab/config.py:10-13, 35-48` | 默认算法、legacy 验签算法、模板、白名单配置 | 配置 | stdlib | 算法切换的唯一配置入口 | **中** | **已完成** |
| `tasks/document_tasks.py:92` | 密钥标识由 `config.key_id_for` 生成 | 算法标识 | — | 将审批人与密钥/算法绑定 | **中** | **已完成**（`{actor}-{algorithm}-01`） |
| `lab/encoding.py:18-20`；`tasks/document_tasks.py:32-64` | 签名字节规范化（sort_keys、紧凑分隔符、UTF-8） | 规范化 JSON（非密码原语） | json（stdlib） | 确保签名/验签双方字节一致 | **无需迁移**（须保持稳定） | 未改动 |
| `tests/test_crypto.py:46-72` | SM2 已知答案/往返/篡改/前导零回归测试 | SM2 | gmssl 3.2.2 | 兼容路径回归 | **中**（仅测试） | 保留且通过 |
| `tests/test_ml_dsa.py`（9 项） | ML-DSA 参数集、Base64 往返、context、共存、端到端 | ML-DSA | pqcrypto 1.0.0 | PQC 行为回归 | **中**（仅测试） | **新增且通过** |
| `tests/test_crypto_agility.py`（13 项） | Base64 规范、注册表、旧数据迁移、业务集成 | 多算法 | — | 密码敏捷性回归 | **中**（仅测试） | **新增且通过** |
| `tests/test_workflow.py:230-242`（235） | 公钥吊销后的重试拒绝测试 | 信任状态 | sqlite3 | 验证吊销语义 | **低**（仅测试） | 保留且通过 |
| `lab/crypto.py:28-33` | SM3 摘要 | SM3-256 | cryptography 46.0.3 | 通用摘要原语 | 无需迁移 | 未改动 |
| `tasks/document_tasks.py:20-29` | 原始文件字节 SM3 | SM3-256 | cryptography 46.0.3 | 材料完整性摘要 | 无需迁移 | 未改动 |
| `tasks/document_tasks.py:100-121`（118-120） | 解密后重算 SM3，并做申请/版本/内容绑定 | SM3-256 | cryptography 46.0.3 | 防篡改、防旧版签名复用到新版本 | 无需迁移 | 未改动 |
| `tasks/workflow_tasks.py:36-40` | 提交请求指纹 SM3 | SM3-256 | cryptography 46.0.3 | 提交幂等去重 | 无需迁移 | 未改动 |
| `tasks/workflow_tasks.py:116` | 审批清单指纹 SM3 | SM3-256 | cryptography 46.0.3 | 审批幂等去重（与随机签名值解耦） | 无需迁移 | 未改动 |
| `tasks/workflow_tasks.py:209` | 解密结果 SM3 完整性校验 | SM3-256 | cryptography 46.0.3 | 受控读取完整性校验 | 无需迁移 | 未改动 |
| `lab/crypto.py:150-167` | SM4-GCM 认证加密（每文档新密钥、96-bit nonce、128-bit tag、AAD） | SM4-128-GCM | cryptography 46.0.3 | 申请材料静态加密（archive_service） | 无需迁移 | 未改动 |
| `lab/crypto.py:169-203` | SM4-GCM 解密 + tag/AAD 校验 | SM4-128-GCM | cryptography 46.0.3 | 审批与读取时受控解密（review/query_service） | 无需迁移 | 未改动 |
| `lab/crypto.py:154-155` | 材料密钥/Nonce 生成（16 B / 12 B） | CSPRNG | secrets（stdlib） | 每次加密唯一密钥，防 nonce 重用 | 无需迁移 | 未改动 |
| `lab/crypto.py:205-207` | 未使用材料密钥销毁 | 密钥生命周期 | sqlite3（stdlib） | 事务失败/回滚清理 | 无需迁移 | 未改动 |
| `lab/auth.py:24-26, 40-42, 52-56` | 口令派生 + 盐 + 常量时间比较 + 会话令牌 | PBKDF2-HMAC-SHA256（260k）+ CSPRNG | hashlib / hmac / secrets（stdlib） | 账号口令存储与会话认证 | 无需迁移 | 未改动 |
| `lab/crypto.py:164, 188-190` | Base64 编解码（信封字段） | 编码（非密码） | base64（stdlib） | Nonce/密文/Tag 序列化 | 无需迁移（非密码操作） | 未改动 |
| `requirements.txt:4` | `pqcrypto` 依赖声明与版本锁定 | 供应链 | pqcrypto 1.0.0 | ML-DSA 原生实现（Rust/PyO3） | **中** | **已声明**；非 FIPS 认证 |
| `self_check.py:5-14` | ML-DSA-65 往返验签自检（含 context） | ML-DSA | pqcrypto 1.0.0 | 部署自检 | **低** | **已完成** |
| `tests/test_crypto.py:18-20, 22-26, 28-44` | SM3 / SM4-ECB / SM4-GCM RFC 8998 已知答案测试 | SM3 / SM4 | cryptography 46.0.3 | 底层算法自检 | 无需迁移 | 未改动 |
| `tests/test_crypto.py:74-107` | SM4-GCM 密钥轮换/篡改/AAD/服务隔离测试 | SM4-GCM | cryptography 46.0.3 | 安全属性回归 | 无需迁移 | 未改动 |

> **v2 状态图例**：`已完成` = 算法/存储/配置已落地并有测试；`只读兼容` = 仅为历史数据保留，新数据不走该路径；`仍存在风险` = 已识别但本项目未处置（见 `SECURITY_REPORT.md` 残余风险）。

---

## 4. 优先级判定依据

### 4.1 为什么 SM2 曾被判定为“高”（v1 基线）

> v1 判定时 SM2 是唯一的生产签名算法，因此全部条目标为“高”。v2 已完成签发路径迁移；本节保留原始判定依据，便于审计迁移理由。

SM2 基于椭圆曲线离散对数问题（ECDLP）。Shor 算法在足够规模、纠错可用的量子计算机上可在多项式时间内求解 ECDLP，进而由公钥恢复私钥。因此以下操作全部失效：

- 密钥生成：生成的 SM2 密钥对不再具备量子安全性（存量密钥也需轮换）。
- 签名/验签：签名可被伪造，不可否认性失效。
- 公钥校验：只是曲线正确性检查，不提供量子安全性。
- 私钥保管：如果私钥被量子攻击恢复，保管层再严密也无意义。
- 信任登记表：登记的还是 SM2 公钥，迁移时必须支持新算法与新密钥。

**v2 处置**：上述五项中，密钥生成/签名已切换 ML-DSA-65，公钥校验与信任登记表已按算法分派，私钥保管仍是未处置风险（`R-01`）。

迁移目标（按 NIST 已发布标准）：

| 用途 | 推荐 PQC 算法 | 说明 | v2 状态 |
|---|---|---|---|
| 数字签名（首选） | **ML-DSA-65 / ML-DSA-87**（FIPS 204） | 基于格的签名，性能与密钥/签名尺寸较均衡 | **已采用 ML-DSA-65 为默认**；44/87 已注册可选 |
| 数字签名（保守/长期归档） | **SLH-DSA**（FIPS 205） | 基于哈希，安全假设保守；签名更大、更慢 | 未实现，保留为路线 |
| 过渡期 | **SM2 + ML-DSA 混合签名** | 两套签名都验证；兼顾商用密码合规与量子抵抗 | **本次未采用**（见下） |

**本次迁移决策**（2026-10-30）：

- 采用“**直接替换、旧数据只读兼容**”：新密钥与新签名一律 ML-DSA-65，历史 SM2 签名仅保留验签路径；
- 暂不实现 `HybridSigner`。原因：混合签名要求在 `aid-approval-v1` 清单之外新增算法列表与双签名字段，属于协议升级；在单机参考实现中收益低于复杂度；
- 该决策的代价是**过渡期内不存在“抗量子 + 国密合规”双重保证**，已作为残余风险记入 `SECURITY_REPORT.md`（`R-07`）。若合规要求变化，扩展点已预留：`Signer.component_algs` 字段与注册表工厂可直接承载 `HybridSigner`。

> 中国商用密码语境下，应同时跟踪国家密码管理部门/密标委的 PQC 标准进展；在国产 PQC 签名标准落地前，**混合签名**仍是风险最低的过渡方案。本报告不虚构具体国标编号。

### 4.2 为什么 SM3 / SM4 / PBKDF2 不需要 PQC 迁移

- **SM3-256**：量子攻击只有 Grover，摘要安全强度从 256-bit 降到约 128-bit（原像）；对本项目的完整性/指纹用途仍然足够。没有 Shor 攻击面。
- **SM4-128-GCM**：对称分组密码，Grover 将 128-bit 密钥搜索降到约 2^64，仍高于现实攻击门槛；认证标签与 AAD 机制不受量子算法直接破坏。无需替换。
- **PBKDF2-HMAC-SHA256**：口令派生属于对称/哈希构造，不受 Shor 威胁。若做安全现代化，可另行评估 Argon2id，但这与 PQC 无关。
- **`secrets` CSPRNG**：随机性来源不依赖公钥数学，无需迁移。

### 4.3 为什么“中”要单独列出

这些资产本身不是非对称算法，但迁移时会**直接阻塞**或**必须同步修改**。v2 的处置结果如下：

- `public_keys` 已增加 `alg`、`encoding`；**仍缺** `key_usage`、`valid_from/valid_to`、`revoked_at`、`key_version`。ML-DSA 公钥为 1.3–2.6 KB，已由 Base64 与算法自声明长度承载（`lab/store.py:18-22`）。
- `approvals.signature` 已改为变长 Base64 并新增 `sig_alg`、`sig_encoding`；不再假设 `r||s` 的 128 hex（`lab/store.py:28-34`）。
- `HEX128` 已迁至 `lab/crypto_encoding.py:9`，仅用于旧 Hex 识别；密钥标识改为模板 `{actor_id}-{algorithm}-01`（`lab/config.py:12`、`tasks/document_tasks.py:92`）。
- 测试向量**未替换**而是**并存**：SM2 KAT 继续锁定兼容路径，ML-DSA 由新增 9 项测试覆盖；既有 50 项测试保持未修改并通过。
- **新增阻塞项**：`pqcrypto` 为 Rust/PyO3 二进制扩展，无 Python 侧可审计实现，且非 FIPS 140 认证模块；生产选型需重新评估。

---

## 5. 关键发现与风险

### 5.1 PQC / 密码敏捷性

1. **非对称算法单一且硬编码**：`HEX128`（原 `lab/crypto.py:24`，现 `lab/crypto_encoding.py:9`）、`HEX64_PATTERN`（`lab/encoding.py:7`）、`<actor>-SM2-01`（`tasks/document_tasks.py:92`）曾把“SM2 + 128 hex”写死。**状态：已缓解**——`Signer` 契约 + `SIGNERS` 注册表已落地（`lab/signers.py:61-104,261-274`），密钥标识改为算法模板。`HEX128` 仅保留旧 Hex 识别，不再参与业务准入。
2. **签名清单缺少算法字段**：`MANIFEST_KEYS` 的 10 个字段中没有 `sig_alg` / `key_version`。**状态：已接受（设计取舍）**——算法经 `signing_key_id → public_keys.alg` 绑定，清单本身不含算法；若做混合签名或同 key_id 轮换，必须升级 `aid-approval-v2`。
3. **信任登记表过于简单**：`public_keys` 原缺算法、用途、有效期、吊销时间、密钥版本。**状态：部分缓解**——已有 `alg`、`encoding`（`lab/store.py:18-22`），同一审批人可同时持有 SM2 与 ML-DSA 密钥（`owner_id` UNIQUE 已移除）；仍缺 `key_usage`、`valid_from/valid_to`、`revoked_at`、`key_version`。
4. **签名/公钥长度假设**：`approvals.signature`、`public_keys.public_key` 原依赖 `HEX128`、`1 <= r,s < n`、`r||s` 等 SM2 专用约束。**状态：已缓解**——对外统一严格 canonical Base64，长度由 `Signer` 子类声明（SM2 64 B / ML-DSA-65 3,309 B），SM2 专用校验内聚在 `SM2Signer.verify`（`lab/signers.py:132-145`）。
5. **没有 KEM / 密钥交换**：当前没有 RSA/ECDH/ML-KEM 的迁移面。这是好消息；但若后续引入 TLS、密钥封装或 KMS，应直接采用 **ML-KEM-768/1024（FIPS 203）** 或国产对应标准，而不是先上 RSA/ECDH。**状态：仍适用**（本次未引入 KEM）。
6. **SM2 用户标识隐式固定**：固定用户标识 `1234567812345678` 由 gmssl 默认行为承担；ML-DSA 没有 ZA 概念。**状态：部分缓解**——`Signer.sign/verify` 已增加 `context` 参数，ML-DSA 透传 FIPS 204 ctx（`lab/signers.py:217-235`，`self_check.py:11-12` 已用 `aid-approval-v1` 验证）；但**业务层尚未启用**，当前域分离仍由清单 `schema` 字段承担。
7. **无私钥保护**：SM2/ML-DSA 私钥以明文存于 `private/keys.sqlite3`，仅靠文件权限 0700/0600（`lab/crypto.py:36-57`）。**状态：仍存在**——ML-DSA-65 私钥为 4,032 B，泄露后果与 SM2 相同；生产必须使用 HSM/KMS。
8. **gmssl 3.2.2 的工程风险**：纯 Python 实现、版本较旧、使用私有 `_kg`、非恒定时间；`lab/signers.py:30-35` 仍在修它的公钥前导 `04` 截断缺陷。**状态：仍存在（仅兼容路径）**——SM2 已退出签发路径，但历史验签仍依赖它；生产应替换为经审计实现。
9. **pqcrypto 供应链与实现风险**（v2 新增）：`pqcrypto 1.0.0` 为 Apache-2.0 的 Rust/PyO3 扩展（Windows 提供 `cp39-abi3` 轮子），无 Python 侧可审计实现、**非 FIPS 140 认证模块**，也未做侧信道评估。**状态：仍存在**——版本已锁定（`requirements.txt:4`），但生产选型需评估认证、审计与长期维护。
10. **旧 Hex 兼容成为降级面**（v2 新增）：无算法提示的验签固定回退 SM2（`lab/config.py:11,38-40`）。攻击者无法借此伪造新签名（算法由登记表 `alg` 决定），但**长期归档数据仍依赖被量子威胁命中的 SM2**。**状态：已接受**——旧数据只读、逐行、无全局开关；退役计划见阶段 4。

### 5.2 非 PQC 但会阻断“改作他用”

1. **传递依赖版本已锁定**：`pycryptodomex==3.24.1` 是 `gmssl 3.2.2` 的运行时依赖，`cffi==2.1.1` 与 `pycparser==3.11` 分别是 `cryptography` 与 `cffi` 的传递依赖，均由 `requirements.txt` 显式固定。**v2 状态：保留**（删除会破坏 gmssl 安装或失去版本锁定）。
2. **固定演示口令 `Lab2026!`**（`lab/auth.py:8`）且在控制台打印（`main.py:75`）——仅可用于演示；真实用途必须移除。**v2 状态：仍在**。
3. **会话只存在内存**（`lab/auth.py:32` 的 `_sessions`）——多进程/重启即失效，不适合 Web/API 部署。**v2 状态：仍在**。
4. **无登录限速/锁定、无密钥轮换/吊销管理界面、无 CI 依赖扫描**——上线前需补齐。**v2 状态：仍在**。
5. **PBKDF2 260k 轮**可用，但口令哈希现代化建议评估 Argon2id/scrypt（与 PQC 无关）。**v2 状态：仍在**。
6. **ML-DSA 私钥体积**：4,032 B 明文私钥直接写入 SQLite，与 SM2 的 32 B 私钥相比放大了备份/日志泄露面。**v2 新增，状态：仍在**。

---

## 6. 建议的 PQC 迁移路线

### 阶段 0：冻结与治理（1–2 天）——【部分完成】

- ✅ 将本 CBOM 纳入仓库，并在 v2 中建立“v1 → v2”变更记录。
- ⚠️ `gmssl` / `cryptography` / `pqcrypto` 均已锁定精确版本（`requirements.txt`）；**依赖漏洞扫描与 CI 尚未接入**。
- ⚠️ 传递依赖 `pycryptodomex` / `cffi` / `pycparser` 已随直接依赖锁定，但仍需纳入依赖漏洞扫描。
- ✅ 迁移策略已明确：**直接切 ML-DSA + 旧 SM2 只读兼容**（2026-10-30 决策），不采用混合签名。

### 阶段 1：密码敏捷性改造（先于换算法）——【已完成】

1. ✅ `public_keys` 已增加 `alg`、`encoding`；⚠️ `key_usage`、`valid_from`、`valid_to`、`revoked_at`、`key_version`、`params` **未实现**。
2. ✅ `approvals` 已增加 `sig_alg`、`sig_encoding`；签名改为变长 Base64。
3. ⚠️ 审批清单**未**增加 `sig_alg`，算法经 `signing_key_id → public_keys.alg` 绑定；`aid-approval-v2` 留待混合签名或轮换需求出现时实施。`canonicalize_manifest` 字节稳定性保持不变。
4. ✅ 签名接口已抽象为 `Signer` ABC；`SM2Signer`、`MLDSASigner` 已实现并注册；`HybridSigner` 仅预留（`component_algs` 字段）。
5. ✅ `HEX128` / `<actor>-SM2-01` 硬编码已移除；密钥 ID 由模板 `{actor_id}-{algorithm}-01` 生成，算法单独存字段。
6. ✅ 双读能力已具备：旧 SM2 签名在保留期内仍可验，新签名走 ML-DSA。

### 阶段 2：引入 PQC（核心）——【已完成，采用直接替换】

1. ✅ T017/T018 在首次启动时生成 ML-DSA-65 密钥对（`lab/context.py:21`、`lab/crypto.py:92-109`）。
2. ✅ 新审批只产生 ML-DSA-65 签名；验签按登记表 `alg` 选择算法。
3. ⚠️ 公钥登记表已有 `alg`，但**没有** `key_usage`；当前按 key_id 前缀/算法隐含用途。
4. ✅ 历史审批保留 SM2 验签路径；新审批只走 ML-DSA。
5. ✅ 测试**未替换** SM2 KAT，而是并存：SM2 KAT 锁定兼容路径，新增 9 项 ML-DSA 测试；混合签名测试因未实现而**不存在**。

### 阶段 3：密钥保护与运维——【未开始】

1. 将私钥从明文 SQLite 移到 HSM/KMS/OS keystore；至少做信封加密与访问审计。
2. 建立密钥轮换、吊销、过期策略；`public_keys.active` 升级为完整生命周期。
3. 记录算法迁移审计事件（`operation=key_migration`），保留旧签名验证能力至归档期满。

### 阶段 4：退役 SM2（按数据保留期）——【未开始】

- 归档期满后停止接受 SM2 验签；仅保留历史验签只读路径直至期满。
- 清理旧密钥材料与测试向量，更新 CBOM 与 SBOM。

### 规模提示（用于容量规划）

| 算法 | 公钥大小 | 签名大小 | 备注 |
|---|---|---|---|
| SM2 | 64 B（128 hex） | 64 B（128 hex） | 当前实现 |
| ML-DSA-44 | 1,312 B | 2,420 B | 最低强度 |
| ML-DSA-65 | 1,952 B | 3,309 B | 推荐默认 |
| ML-DSA-87 | 2,592 B | 4,627 B | 高安全 |
| SLH-DSA（128s 级） | ~32 B | ~7.9 KB | 保守/长期归档，慢 |

> 迁移后 `approvals` / `public_keys` 的存储、审计日志、备份体积都会上升；若走混合签名，签名体积约为两者之和。

---

## 7. 附录

### 7.1 未纳入 CBOM 的非密码安全控制

以下内容重要，但不属于密码原语，故未列入主表：

- 文件权限 `chmod(0o700/0o600)`（`lab/crypto.py:53-57`）
- JSON 重复键/NaN 拒绝（`lab/encoding.py:23-40`）
- SQLite 事务与 `BEGIN IMMEDIATE`（`lab/store.py:86-98`）
- 会话令牌校验（`lab/auth.py:59-70`）
- 审计事件白名单（`lab/context.py:40-59`）
- 角色/资源/状态授权（`tasks/access_tasks.py:12-66`）

### 7.2 仅测试代码中的密码操作

- `tests/test_crypto.py:22-26` 使用 SM4-ECB 仅做单分组已知答案测试；ECB 不用于业务数据。
- `tests/test_workflow.py:101-102` 使用 Base64 仅构造篡改密文，不涉及密钥。
- SM2 已知答案/伪签名/前导零回归在 v2 中**保留**（锁定兼容路径），未替换为 ML-DSA 向量；ML-DSA 向量单独放在 `tests/test_ml_dsa.py`。

### 7.3 机器可读 CBOM

本文件是人工可读的 Markdown CBOM。若需要接入 CI/SCA 平台，可进一步生成 **CycloneDX 1.6 CBOM（JSON）**，把 `bom-ref`、`cryptoProperties.assetType`、`algorithmProperties`、`nistQuantumSecurityLevel` 等字段结构化。**v2 仍未提供机器可读版本**，这是已知交付缺口。

### 7.4 测试证据索引（v2）

| 安全属性 | 测试文件 | 用例 |
|---|---|---|
| Base64 规范编码 / 非规范拒绝 | `tests/test_crypto_agility.py` | `Base64EncodingTests.test_non_canonical_and_malformed_base64_rejected` |
| 算法不从长度推断 | `tests/test_crypto_agility.py` | `SignerRegistryTests.test_algorithm_is_not_inferred_from_value_length` |
| 旧 Hex 只读兼容 | `tests/test_crypto_agility.py` | `LegacyCompatibilityTests.test_legacy_hex_is_read_only_compatible` |
| 旧库 schema 平滑迁移 | `tests/test_crypto_agility.py` | `LegacyCompatibilityTests.test_old_database_schema_is_migrated` |
| ML-DSA 往返 / 篡改拒绝 | `tests/test_ml_dsa.py` | `MLDSASignerTests.test_ml_dsa_65_roundtrip_and_tamper` |
| 参数集尺寸与注册 | `tests/test_ml_dsa.py` | `MLDSASignerTests.test_parameter_sets_are_registered_and_sized` |
| context 域分离 | `tests/test_ml_dsa.py` | `MLDSASignerTests.test_ml_dsa_context_domain_separation` |
| SM2 / ML-DSA 密钥共存 | `tests/test_ml_dsa.py` | `KeyCoexistenceTests.*` |
| 默认 ML-DSA 下端到端审批 | `tests/test_ml_dsa.py` | `MLDSAWorkflowTests.test_ml_dsa_approval_end_to_end` |

完整的威胁—控制—证据映射见 [`SECURITY_REPORT.md`](SECURITY_REPORT.md) 第 8 章。

---

**报告结论（v2）**：签名链的 PQC 迁移已经完成——ML-DSA-65 成为默认签名算法，SM2 仅保留历史验签。SM3、SM4-GCM、PBKDF2、CSPRNG 保持不动。真正的工作量确实不在“把 SM2 换成 ML-DSA”这一行代码，而在**算法标识、变长编码、信任登记表、迁移兼容与测试矩阵**；这些已在 v2 落地。剩余风险已经转移：不再是“算法会被量子破解”，而是**私钥明文存储**与**第三方密码实现的认证/审计状态**。
