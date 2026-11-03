# 安全威胁建模报告（Security Threat Modeling Report）

| 项目 | 内容 |
|---|---|
| **文档版本** | v1.0 |
| **日期** | 2026-10-31 |
| **适用系统** | 密码敏捷审批与安全归档框架（`secure-approval-system-pqc`） |
| **适用代码** | 当前工作区，ML-DSA 迁移完成后 |
| **方法** | STRIDE（按信任边界展开）+ 攻击树 + 可能性 × 影响风险矩阵 + 测试证据映射 |
| **关联文档** | [`README.md`](README.md)（使用与配置）、[`CBOM.md`](CBOM.md)（密码物料清单 v2） |
| **测试基线** | 72 项自动化测试全部通过（50 既有 + 13 密码敏捷性 + 9 ML-DSA） |

> **文档定位**：本报告回答“系统面临什么威胁、现有控制是否真实存在、还剩什么风险、用什么测试证明”。它不是功能说明书，也不替代渗透测试、侧信道评估或形式化验证。

---

## 1. 执行摘要

**整体姿态**：系统完成了从 SM2 到 **ML-DSA-65（FIPS 204）** 的签名算法迁移，新审批签名已具备量子抗性；历史 SM2 签名仅保留只读验签。迁移没有改变系统的部署形态（单机、无 TLS、无 HSM），因此**主要残余风险不在算法，而在密钥保护、身份认证与第三方密码实现**。

**本次迁移对攻击面的净变化**：

| 变化 | 方向 | 说明 |
|---|---|---|
| 新审批签名的量子伪造风险 | **降低** | ML-DSA-65 基于格问题，不受 Shor 算法影响 |
| 算法混淆 / 按长度猜算法 | **降低** | 算法由 `signing_key_id → public_keys.alg` 绑定，未注册算法直接拒绝 |
| 变长数据带来的编码歧义 | **降低** | 严格 canonical Base64，非规范形式一律拒绝 |
| 第三方密码实现依赖 | **上升** | 新增 `pqcrypto`（Rust/PyO3 二进制扩展，非 FIPS 140 认证） |
| 历史 SM2 数据的长期可信性 | **不变（已接受）** | 归档期内仍依赖 SM2 验签，量子时代可被伪造 |
| 私钥保护 | **不变（仍为高风险）** | ML-DSA 私钥 4,032 B 明文存入 SQLite |

**Top 5 残余风险**：

| 编号 | 风险 | 等级 | 是否本次可处置 |
|---|---|---|---|
| `R-01` | 签名私钥（SM2/ML-DSA）明文存储，仅靠文件权限 | **高** | 否，需 HSM/KMS |
| `R-02` | `pqcrypto` 非 FIPS 140 认证、无 Python 侧可审计实现 | **高**（生产） | 否，需选型评估 |
| `R-03` | 历史 SM2 审批在量子时代可被伪造，归档证据长期不可否认性受损 | **中** | 否，按保留期接受 |
| `R-05` | 固定演示口令、会话仅存内存 | **高**（生产） | 是，部署前替换 |
| `R-06` | 无 TLS/CA，网络边界不存在 | **高**（生产） | 否，属部署架构 |

> 判定口径：等级针对**生产复用**评估；作为单机参考实现，`R-05`/`R-06` 属于明确的“非目标”。

---

## 2. 系统描述与信任边界

### 2.1 业务流程

1. 学生提交材料 → SM3 计算文件摘要与幂等指纹 → SM4-GCM 加密归档；
2. 辅导员在终端确认 → 构造 10 字段规范化清单 → 使用私钥签名（默认 ML-DSA-65）；
3. 系统验签（按登记表算法）→ 幂等去重 → 解密并重算 SM3 校验绑定 → 同一事务写入审批、请求记录与审计；
4. 财务/审计等角色按授权读取或审计。

### 2.2 组件与信任边界

```text
┌────────────────────┐        TB1: 用户终端 ↔ 应用进程（stdin，无 TLS）
│ 学生 / 辅导员 / 财务 │
└─────────┬──────────┘
          ▼
┌──────────────────────────────────────────────┐
│ 应用进程（main.py / tasks/ / lab/）            │
│  Auth → Context → Store / Crypto              │
└───┬───────────────┬───────────────┬──────────┘
    │ TB2           │ TB3           │ TB4
    ▼               ▼               ▼
┌────────────┐ ┌─────────────┐ ┌──────────────────────────┐
│ 业务 SQLite │ │ 密钥 SQLite │ │ 第三方密码库              │
│ 审批/审计   │ │ 私钥明文     │ │ gmssl / cryptography /   │
│ 幂等/公钥   │ │ 0700 / 0600 │ │ pqcrypto                 │
└────────────┘ └─────────────┘ └──────────────────────────┘
    ▲
    │ TB6: 历史数据（SM2 + Hex）↔ 新数据（ML-DSA + Base64）
```

| 边界 | 说明 | 关键控制 |
|---|---|---|
| TB1 用户 ↔ 应用 | 单机控制台，无网络传输 | 口令认证 + 会话令牌；**无 TLS** |
| TB2 应用 ↔ 业务库 | 进程内 SQLite | `BEGIN IMMEDIATE` 事务、外键、审计白名单 |
| TB3 应用 ↔ 密钥库 | 进程内 SQLite，明文私钥 | `owner_id` 绑定、文件权限 0700/0600 |
| TB4 应用 ↔ 密码库 | Python 调用本地库 | 版本锁定；gmssl 纯 Python、pqcrypto 二进制扩展 |
| TB6 历史 ↔ 新数据 | 同一表内两种算法/编码 | 行级 `alg`/`encoding`，无全局降级开关 |

### 2.3 攻击者假设

| 攻击者 | 能力 | 主要目标 |
|---|---|---|
| 外部网络攻击者 | 无（本系统无网络接口） | — |
| 本地文件攻击者 | 可读取用户目录（权限绕过/备份泄露） | 私钥、材料、审计记录 |
| 已认证的恶意用户 | 拥有合法账号，可构造任意清单/密文 | 越权审批、伪造签名、重放 |
| 供应链攻击者 | 可污染 `pip` 依赖 | 在密码库中植入后门 |
| 量子攻击者（长期） | 未来拥有可运行 Shor 的量子计算机 | 伪造历史 SM2 签名、恢复 SM2 私钥 |

### 2.4 不在本次范围

- 操作系统与 Python 解释器自身漏洞；
- `pip` 供应链之外的构建系统（本项目无 CI/CD）；
- 物理入侵、内存取证、冷启动攻击；
- 侧信道与故障注入（见第 9 章声明）。

---

## 3. 资产与安全目标

| 编号 | 资产 | 机密性 | 完整性 | 可用性 | 不可否认性 | 主要保护 |
|---|---|:---:|:---:|:---:|:---:|---|
| A1 | 申请材料原文 | 高 | 高 | 中 | — | SM4-128-GCM + SM3 |
| A2 | 材料加密密钥/Nonce | 高 | 高 | 中 | — | 每文档新密钥；存于密钥库 |
| A3 | 审批签名私钥（SM2/ML-DSA） | **最高** | **最高** | 中 | — | `owner_id` 绑定、文件权限；**明文存储** |
| A4 | 可信公钥登记表 | — | 高 | 中 | — | `key_id → (public_key, alg, encoding, active)` |
| A5 | 审批凭证（清单 + 签名） | 低 | 高 | 中 | **高** | 算法绑定验签 + 清单规范化 |
| A6 | 审计事件 | 低 | 高 | 中 | 高 | 同一事务写入 + 枚举白名单 |
| A7 | 口令哈希 / 会话令牌 | 高 | 高 | 中 | — | PBKDF2 260k + 常量时间比较 |
| A8 | 幂等记录（request_id → 结果） | 低 | 高 | 中 | 中 | 主键 + 指纹比对 |

**安全目标**：

1. **机密性**：材料仅授权角色可解密；私钥不离开本机（当前边界）。
2. **完整性**：材料、清单、审批记录不可被静默篡改。
3. **不可否认性**：审批人无法否认其签发行为；签名算法具备长期安全性。
4. **算法敏捷性**：算法可替换、旧数据可验、迁移不破坏历史证据。

---

## 4. 威胁建模方法

### 4.1 STRIDE 与系统元素

| STRIDE 类别 | 对应威胁 | 主要作用点 |
|---|---|---|
| Spoofing（身份伪造） | `T-AUTH-01`、`T-ID-01`、`T-SIG-01`、`T-REP-01` | 登录、签名、审批提交 |
| Tampering（篡改） | `T-ALG-01`、`T-ALG-02`、`T-ENC-01`、`T-AUD-01` | 清单、编码、数据库 |
| Repudiation（抵赖） | `T-DOM-01`、`T-HYB-01`、`T-KEY-02` | 签名域、密钥生命周期 |
| Information Disclosure（泄露） | `T-KEY-01`、`T-IMP-01`、`T-NET-01` | 密钥库、密码实现、传输 |
| Denial of Service（拒绝服务） | `T-DOS-01` | 大尺寸输入/签名 |
| Elevation of Privilege（提权） | `T-ID-01`、`T-KEY-02` | 角色/密钥归属 |

### 4.2 风险评级

- **可能性**：1 = 需要特殊条件；2 = 在特定部署下可能；3 = 默认配置下可发生。
- **影响**：1 = 局部/可恢复；2 = 单条业务记录受损；3 = 私钥泄露/大规模伪造/合规失效。
- **等级**：乘积 1–2 = 低；3–4 = 中；6–9 = 高。
- 评级针对**生产复用**；参考实现的“非目标”会在备注中说明。

### 4.3 威胁编号与状态

- `T-*`：威胁条目；`R-*`：残余风险（第 7 章）；`A*`：资产（第 3 章）。
- 状态：`已缓解`（控制存在且有测试）、`部分缓解`（控制存在但覆盖不全）、`已接受`（明确不处置）、`未处置`（待办）。

### 4.4 方法限制

本报告基于**源码审查 + 自动化测试结果 + 依赖元数据**，未执行渗透测试、模糊测试、侧信道测量或形式化验证。所有“已缓解”结论均给出来源文件/行号或测试用例；无法给出证据的控制不写入“已缓解”。

---

## 5. 威胁目录

### 5.1 身份与认证

| 编号 | STRIDE | 攻击场景 | 现有控制（证据） | 残余风险 | 状态 |
|---|---|---|---|---|---|
| `T-AUTH-01` | Spoofing | 攻击者猜测/暴力破解固定演示口令；窃取内存会话 | 口令 PBKDF2-HMAC-SHA256 260k 轮 + 随机盐；`hmac.compare_digest` 常量时间比较；会话令牌 32 字节随机（`lab/auth.py:24-26,40-42,52-56`）；每次操作复核主体、角色与 active 状态（`lab/auth.py:59-70`） | 口令固定为 `Lab2026!` 并打印到控制台；会话仅存进程内存；无登录限速/锁定 | **部分缓解**（演示环境明确非目标） |
| `T-ID-01` | Spoofing / Elevation | 使用他人密钥签名；把合法签名安到其他审批人/申请上 | 清单 `approver_id` 必须等于登录主体（`tasks/access_tasks.py:80-81`）；密钥 `owner_id` 必须匹配（`:85-86`）；私钥取用按 `owner_id` 绑定（`lab/crypto.py:111-117`）；业务授权独立于签名有效性（`tasks/access_tasks.py:12-66`） | 超级管理员若可直接改库仍可替换公钥；无密钥轮换界面 | **已缓解**（有测试） |

### 5.2 算法与签名

| 编号 | STRIDE | 攻击场景 | 现有控制（证据） | 残余风险 | 状态 |
|---|---|---|---|---|---|
| `T-ALG-01` | Tampering / Spoofing | 诱导系统用弱算法验签（类似 JWT `alg=none`）；按输入长度猜算法 | 算法**不从请求推断**：`signing_key_id → public_keys.alg`（`tasks/access_tasks.py:82-88`）；未注册算法抛 `UNSUPPORTED_ALGORITHM`（`lab/signers.py:269-274`）；不提供 128 hex → SM2 的隐式路径 | 无 | **已缓解**（`test_algorithm_is_not_inferred_from_value_length`） |
| `T-ALG-02` | Tampering / Repudiation | 同一 key_id 下轮换算法导致验签歧义；混合签名无法表达 | 算法随密钥登记；`signing_keys.owner_id` UNIQUE 已移除，允许 SM2/ML-DSA 共存（`lab/crypto.py:64-80`） | 清单无 `sig_alg`/`key_version`；同一 key_id 不能换算法；混合签名未实现 | **部分缓解**（设计取舍） |
| `T-SIG-01` | Spoofing / Tampering | 伪造或篡改审批签名；用错误签名通过验签 | ML-DSA 验签异常统一映射为 `False`（`lab/signers.py:225-235`）；SM2 校验 `r/s` 范围与曲线点（`:132-145`）；签名失败抛 `SIGNATURE_INVALID`（`tasks/access_tasks.py:87-89`） | 密码库自身正确性依赖第三方实现 | **已缓解**（往返 + 篡改测试） |
| `T-DOM-01` | Repudiation / Spoofing | 把在 A 协议产生的合法签名挪用到 B 协议 | 清单固定 10 字段并含 `schema="aid-approval-v1"`，参与签名字节（`tasks/document_tasks.py:42-64,84-95`）；ML-DSA 支持 FIPS 204 `context`（`lab/signers.py:217-235`） | 业务层尚未传 `context`，当前域分离依赖 `schema` 字段 | **部分缓解** |
| `T-HYB-01` | Repudiation / 合规 | 过渡期缺少“抗量子 + 国密合规”双重保证 | 明确决策：直接替换，旧数据只读（`CBOM.md` 4.1）；`Signer.component_algs` 预留扩展点（`lab/signers.py:75`） | 无混合签名；若监管要求双签，需协议升级 | **已接受**（对应 `R-07`） |

### 5.3 编码、重放与审计

| 编号 | STRIDE | 攻击场景 | 现有控制（证据） | 残余风险 | 状态 |
|---|---|---|---|---|---|
| `T-ENC-01` | Tampering | 构造非规范 Base64（尾部比特不同、缺失/多余 padding、URL-safe、空白）造成签名比对歧义 | `b64_to_bytes_strict` 校验字母表、padding、长度与规范往返（`lab/crypto_encoding.py:20-30`）；业务新写入固定 Base64（`lab/config.py:44`） | 旧 Hex 兼容面仍存在（见 `T-MIG-01`） | **已缓解**（`test_non_canonical_and_malformed_base64_rejected`） |
| `T-REP-01` | Spoofing | 重放审批请求，重复产生业务效果 | `request_id` 幂等：同指纹返回原结果并记 `REPLAY`，异指纹抛 `REQUEST_CONFLICT`（`tasks/workflow_tasks.py:128-135`）；指纹为规范化清单 SM3（`:116`）；验签先于去重（`:122-126`）；审批、请求记录、审计同事务（`:118-173`） | 内存会话无跨进程共享；跨库重放超出范围 | **已缓解**（历史 workflow 测试） |
| `T-AUD-01` | Repudiation | 删除/篡改审计日志，使拒绝行为不可追溯 | 拒绝事件在业务事务回滚后独立写入（`lab/context.py:61-66`）；审计字段经枚举与 ID 白名单过滤（`:40-59`）；成功审计与业务同事务提交（`tasks/workflow_tasks.py:171-172`） | 审计表无哈希链/外部锚定，拥有 DB 写权限者可删改 | **部分缓解** |

### 5.4 密钥与迁移

| 编号 | STRIDE | 攻击场景 | 现有控制（证据） | 残余风险 | 状态 |
|---|---|---|---|---|---|
| `T-KEY-01` | Information Disclosure | 读取 `keys.sqlite3` 获得 SM2/ML-DSA 私钥，伪造任意审批 | 目录 0700、文件 0600（`lab/crypto.py:53-57`）；私钥按 `owner_id` 绑定（`:111-117`） | **私钥明文存储**；ML-DSA-65 私钥 4,032 B；备份/日志/磁盘镜像均可泄露 | **未处置**（`R-01`） |
| `T-KEY-02` | Repudiation / Elevation | 密钥泄露后无法轮换/吊销；旧密钥长期可用 | `public_keys.active` 支持吊销，验签拒绝 inactive 密钥（`tasks/access_tasks.py:83-84`）；`test_workflow` 覆盖吊销后重试拒绝 | 无轮换界面/流程、无有效期、无 `revoked_at`、无密钥版本 | **部分缓解**（`R-09`） |
| `T-MIG-01` | Spoofing / Downgrade | 利用旧 Hex/SM2 兼容路径绕过新算法要求 | 旧数据逐行标记 `encoding="hex"`/`alg="SM2"`；新写入固定 Base64（`lab/config.py:44`）；无全局“允许 Hex”开关；无提示验签固定回退 SM2 而非按长度猜测（`lab/crypto.py:139-148`） | 历史 SM2 签名在量子时代可被伪造；归档期内仍须验签 | **已接受**（`R-03`） |

### 5.5 实现与供应链

| 编号 | STRIDE | 攻击场景 | 现有控制（证据） | 残余风险 | 状态 |
|---|---|---|---|---|---|
| `T-IMP-01` | Information Disclosure | 通过时间侧信道恢复私钥/随机数 | SM2 随机 k 由 `secrets.randbelow` 生成（`lab/signers.py:125-128`）；SM4 密钥/Nonce 由 `secrets` 生成（`lab/crypto.py:154-155`） | `gmssl 3.2.2` 纯 Python、非恒定时间、使用私有 `_kg`；pqcrypto 未做侧信道评估 | **未处置**（`R-04`） |
| `T-SUP-01` | Tampering | 依赖包被投毒或实现有缺陷，导致签名可伪造/私钥泄露 | 版本精确锁定（`requirements.txt`）；`pqcrypto` 延迟导入，缺失时 `CRYPTO_UNAVAILABLE`（`lab/signers.py:203-208`） | 无依赖漏洞扫描/哈希校验；pqcrypto 为 Rust/PyO3 二进制扩展，非 FIPS 140 认证；gmssl 版本较旧 | **未处置**（`R-02`） |
| `T-SUP-02` | Tampering | 传递依赖被投毒或版本漂移，扩大供应链面 | 全部依赖均在 `requirements.txt` 中精确锁定；`pycryptodomex` 为 `gmssl` 的运行时依赖，`cffi` / `pycparser` 为 `cryptography` 的传递依赖 | 无依赖漏洞扫描/哈希校验；传递依赖仍需持续跟踪 CVE | **未处置**（`R-10`） |

### 5.6 可用性与部署

| 编号 | STRIDE | 攻击场景 | 现有控制（证据） | 残余风险 | 状态 |
|---|---|---|---|---|---|
| `T-DOS-01` | DoS | 提交超大公钥/签名/密文耗尽内存；ML-DSA 3.3 KB 签名放大日志与存储 | 公钥/签名长度由算法声明并严格校验（`lab/signers.py:192-201,225-229`）；材料限制 1 MiB（`tasks/workflow_tasks.py:9,33`）；密文上限 1 MiB、nonce 12 B、tag 16 B（`lab/crypto.py:191-192`） | 无速率限制；审计/备份体积随 ML-DSA 签名增大 | **部分缓解** |
| `T-NET-01` | Information Disclosure / Tampering | 中间人窃听或篡改（若部署为网络服务） | 当前为单机控制台，无网络接口 | 无 TLS、无 CA、无证书链；一旦改为 Web/API 部署即暴露 | **不适用（当前）** / **未处置（部署时）**（`R-06`） |

---

## 6. PQC 专项分析

### 6.1 量子威胁映射

| 原语 | 量子算法 | 影响 | 本项目结论 |
|---|---|---|---|
| SM2（ECC 签名） | Shor | 由公钥恢复私钥，签名可伪造 | 已退出签发；历史验签仍受影响 |
| ML-DSA-65 | 已知量子算法无有效攻击 | 基于 Module-LWE/SIS | 作为默认签名 |
| SM3-256 | Grover | 原像强度约降至 128-bit | 完整性/指纹用途仍足够 |
| SM4-128-GCM | Grover | 密钥搜索约降至 2^64 | 认证加密仍可用 |
| PBKDF2 / CSPRNG | 无直接加速 | — | 无需迁移 |
| KEM / 密钥交换 | — | 系统内不存在 | 无迁移面；未来引入直接用 ML-KEM（FIPS 203） |

### 6.2 Harvest-now / forge-later（先收集、后伪造）

签名与加密的量子风险不同：**签名不需要“先收集密文”**，攻击者只需在未来获得公钥即可伪造新签名；但对于**已归档的审批凭证**，一旦 SM2 被量子攻破，历史签名将失去不可否认性。本系统的处置是：

- 新审批全部改用 ML-DSA-65，避免新增量子脆弱证据；
- 历史 SM2 数据保留验签能力至归档期满，**明确接受**其在量子时代的可信性下降（`R-03`）；
- 无“重新签名历史数据”机制，因为重签需要原始私钥与审批人在线，超出本原型范围。

### 6.3 算法混淆与降级（PQC 语境）

PQC 迁移引入的新降级面是“同一系统同时支持 SM2 与 ML-DSA”。本系统的防线：

1. 算法不来自请求，而来自服务端可信登记表（`public_keys.alg`）；
2. `UNSUPPORTED_ALGORITHM` 硬失败，不回退默认算法；
3. 尺寸互斥：SM2 的 64 B 公钥/签名无法通过 ML-DSA 的严格长度校验（`test_ml_dsa_rejects_sm2_sized_material`）；
4. 无提示验签固定走 `LEGACY_VERIFY_ALGORITHM="SM2"`，只用于历史数据，不会被新数据命中。

### 6.4 域分离（context）

FIPS 204 的 `context` 是算法级域分离参数。当前状态：

- **签名层已支持**：`MLDSASigner.sign/verify` 透传 `context`（`lab/signers.py:217-235`），`self_check.py:11-12` 与 `test_ml_dsa_context_domain_separation` 已验证；
- **业务层未启用**：`Context.prepare_approval` 调用 `crypto.sign` 时未传 `context`（`lab/context.py:84-85`）；
- 当前域分离由清单 `schema="aid-approval-v1"` 参与签名字节承担；
- 启用 context 需要协议版本升级（`aid-approval-v2`），否则会破坏历史签名验证。

### 6.5 尺寸副作用

| 对象 | SM2 | ML-DSA-65 | 倍数 |
|---|---:|---:|---:|
| 公钥 | 64 B | 1,952 B | 30.5× |
| 签名 | 64 B | 3,309 B | 51.7× |
| 私钥 | 32 B | 4,032 B | 126× |

影响：`approvals`、`public_keys`、审计/备份体积上升；Base64 后公钥 2,604 字符、签名 4,412 字符。已通过变长字段与严格长度校验承载；未发现业务层的定长假设残留。

### 6.6 实现可信度

`pqcrypto 1.0.0` 提供 ML-DSA-44/65/87 的原生实现（Rust/PyO3），优点是性能与 API 简洁，缺点是：

- **非 FIPS 140 认证模块**，不能直接用于合规场景；
- 二进制扩展，Python 层无法审计内部实现；
- 未做侧信道/故障注入评估；
- 供应链完整性仅靠版本锁定，无哈希/签名校验。

这些均已记入 `R-02`，不影响参考实现的结论，但生产选型必须重新评估。

### 6.7 混合签名（未实现）

按“直接替换、旧数据只读兼容”的决策，本次不实现 `HybridSigner`。后果：

- 新数据只有 ML-DSA，**不含国密 SM2 签名**；若监管要求“商用密码合规 + 抗量子”同时满足，当前方案不达标（`R-07`）；
- 扩展点已预留：`Signer.component_algs`、注册表工厂、`aid-approval-v2` 的 `sig_alg`/`key_version` 字段设计；
- 混合签名的安全语义（AND 而非 OR）必须在协议层明确，不能由验签方自行选择。

---

## 7. 风险矩阵与处置计划

| 编号 | 关联威胁 | 风险描述 | 可能性 | 影响 | 等级 | 处置建议 | 阶段 | 状态 |
|---|---|---|---:|---:|---|---|---|---|
| `R-01` | `T-KEY-01` | 私钥明文存于 SQLite，文件权限是唯一防线 | 2 | 3 | **高** | 迁 HSM/KMS 或至少信封加密 + 访问审计 | CBOM 阶段 3 | 未处置 |
| `R-02` | `T-SUP-01` | pqcrypto 非 FIPS 认证、二进制不可审计；无依赖扫描 | 2 | 3 | **高** | 生产选型评估认证实现；加入 SCA/哈希校验 | 阶段 0/3 | 未处置 |
| `R-03` | `T-MIG-01` | 历史 SM2 审批在量子时代可被伪造 | 2 | 2 | **中** | 按保留期接受；期满停止验签；可选重签机制 | 阶段 4 | 已接受 |
| `R-04` | `T-IMP-01` | gmssl 非恒定时间、纯 Python；pqcrypto 未做侧信道评估 | 2 | 2 | **中** | 用经审计实现/HSM 替换 gmssl；对 ML-DSA 做侧信道评估 | 阶段 3 | 未处置 |
| `R-05` | `T-AUTH-01` | 固定演示口令、会话仅内存、无限速 | 3 | 2 | **高**（生产） | 部署前强制改口令、外置会话、加限速 | — | 演示非目标 |
| `R-06` | `T-NET-01` | 无 TLS/CA；若改 Web 部署即暴露 | 2 | 3 | **高**（生产） | 网络部署时前置 TLS 终止与证书体系 | — | 演示非目标 |
| `R-07` | `T-HYB-01` | 无混合签名，缺“抗量子 + 国密合规”双重保证 | 2 | 2 | **中** | 需要时实现 `HybridSigner` + `aid-approval-v2` | 阶段 2 延伸 | 已接受 |
| `R-08` | `T-ALG-02` | 清单无 `sig_alg`/`key_version`，轮换/混合表达受限 | 2 | 2 | **中** | 协议升级 `aid-approval-v2` | 未来 | 已接受 |
| `R-09` | `T-KEY-02` | 无密钥轮换/有效期/吊销流程 | 2 | 2 | **中** | 完整密钥生命周期 + 管理界面 | 阶段 3 | 未处置 |
| `R-10` | `T-SUP-02` | 传递依赖（`pycryptodomex` / `cffi` / `pycparser`）版本漂移或漏洞 | 2 | 1 | **低** | 持续锁定版本并接入依赖扫描/哈希校验 | 阶段 0 | 未处置 |
| `R-11` | `T-AUD-01` | 审计日志无哈希链/外部锚定 | 2 | 2 | **中** | 审计链哈希 + 定期导出锚定 | 阶段 3 | 未处置 |
| `R-12` | `T-DOM-01` | 业务层未启用 context 域分离 | 1 | 1 | **低** | 随 `aid-approval-v2` 启用 | 未来 | 已接受 |
| `R-13` | `T-DOS-01` | 无速率限制；ML-DSA 签名放大审计/备份体积 | 2 | 1 | **低** | 加请求限速、审计归档压缩/分级保留 | 阶段 3 | 未处置 |

---

## 8. 测试证据映射

> 基线：`python run_tests.py` → **72 tests, OK**。既有 50 项测试在 `run_tests.py` 中钉住 `AID_SIGNING_ALGORITHM=SM2`（`run_tests.py:12`），ML-DSA 行为由 `tests/test_ml_dsa.py` 显式覆盖。

| 威胁 | 测试文件 | 关键用例 | 断言要点 |
|---|---|---|---|
| `T-ALG-01` | `tests/test_crypto_agility.py` | `test_algorithm_is_not_inferred_from_value_length` | 未注册算法抛 `UNSUPPORTED_ALGORITHM`，不按 128 hex 推断 |
| `T-ALG-01` | `tests/test_crypto_agility.py` | `test_unknown_algorithm_is_rejected` | `ML-DSA-99`/`RSA`/空串均拒绝 |
| `T-ENC-01` | `tests/test_crypto_agility.py` | `test_non_canonical_and_malformed_base64_rejected` | `AB==`、缺 padding、空白、URL-safe、多余 `=` 全部拒绝 |
| `T-ENC-01` | `tests/test_crypto_agility.py` | `test_signature_is_base64_and_roundtrips` | 88 字符 Base64、往返成功、篡改失败 |
| `T-MIG-01` | `tests/test_crypto_agility.py` | `test_legacy_hex_is_read_only_compatible` | 无提示 Hex SM2 可验签；篡改失败 |
| `T-MIG-01` | `tests/test_crypto_agility.py` | `test_old_database_schema_is_migrated` | 旧 `public_keys`/`approvals` 自动补列，旧行保持 `hex` |
| `T-MIG-01` | `tests/test_ml_dsa.py` | `test_hex_sm2_verifies_without_hint_even_when_default_is_ml_dsa` | 默认 ML-DSA 时旧 Hex 仍可验 |
| `T-SIG-01` | `tests/test_ml_dsa.py` | `test_ml_dsa_65_roundtrip_and_tamper` | 尺寸 1952/3309、往返成功、篡改失败 |
| `T-SIG-01` | `tests/test_ml_dsa.py` | `test_ml_dsa_tampered_approval_rejected` | 篡改 `decision` 抛 `SIGNATURE_INVALID` |
| `T-SIG-01` | `tests/test_ml_dsa.py` | `test_ml_dsa_rejects_sm2_sized_material` | SM2 64 B 材料不被 ML-DSA 接受 |
| `T-DOM-01` | `tests/test_ml_dsa.py` | `test_ml_dsa_context_domain_separation` | 不同 context 验签失败；缺 context 也失败 |
| `T-ALG-02` | `tests/test_ml_dsa.py` | `test_sm2_and_ml_dsa_keys_coexist_for_same_owner` | 同一主体两把密钥共存且各自可用 |
| `T-ALG-02` | `tests/test_ml_dsa.py` | `test_legacy_unique_schema_migrates_to_multikey` | 旧 UNIQUE schema 平滑迁移 |
| `T-ALG-01` | `tests/test_ml_dsa.py` | `test_parameter_sets_are_registered_and_sized` | 44/65/87 参数集注册与尺寸正确 |
| `T-ID-01` | `tests/test_crypto.py`、`tests/test_workflow.py` | `test_signer_cannot_use_other_private_key`、`test_forged_principal_is_not_an_authenticated_session`、`test_T05_other_student_and_auditor_never_trigger_decrypt` | 密钥归属/会话主体不一致即拒绝；未授权不触发解密 |
| `T-REP-01` | `tests/test_workflow.py` | `test_concurrent_identical_approvals_have_exactly_one_effect`、`test_retry_with_new_random_signature_still_has_one_effect`、`test_different_request_ids_cannot_approve_same_version_twice` | 同请求幂等、随机签名不影响去重、异请求不能重复审批 |
| `T-KEY-02` | `tests/test_workflow.py` | `test_current_account_and_key_revocation_are_checked_on_retry` | 吊销后重试拒绝 |
| `T-ENC-01`/`T-SIG-01` | `tests/test_ml_dsa.py`、`self_check.py` | 端到端审批 + 自检 | ML-DSA-65 审批闭环；pqcrypto 1.0.0 往返 |

**未覆盖**：侧信道、依赖投毒、SQLite 文件级攻击、网络边界攻击——这些属于第 9 章声明的非目标，不能由现有测试证明。

---

## 9. 已知边界与不适用声明

1. **参考实现**：单机控制台、固定演示口令、无 TLS、无 CA、无 HSM/KMS，不作为生产系统。
2. **未做安全评估**：本报告未执行渗透测试、模糊测试、侧信道测量、故障注入或形式化验证；“已缓解”仅表示代码控制与自动化测试存在。
3. **pqcrypto 非 FIPS 140 认证**：ML-DSA 实现正确性依赖第三方二进制扩展；生产需重新选型。
4. **gmssl 实现风险**：SM2 兼容路径仍使用纯 Python、非恒定时间实现；仅用于历史验签。
5. **私钥明文**：SM2/ML-DSA 私钥均以明文存入本地 SQLite，仅靠 0700/0600 权限。
6. **配置白名单未生效**：`AID_ALLOWED_SIGNING_ALGORITHMS` 仅解析，未参与准入校验；实际可用算法由 `SIGNERS` 注册表决定。
7. **context 未在业务启用**：域分离当前依赖清单 `schema` 字段；启用需协议升级。
8. **旧 SM2 的量子脆弱性**：历史审批在量子时代可被伪造；已在 `R-03` 接受。
9. **测试钉住 SM2**：`run_tests.py` 将既有套件钉在 SM2，以避免通过修改断言使测试通过；这不代表生产默认算法是 SM2。
10. **无机器可读 CBOM**：当前仅 Markdown；接入 SCA/CI 需生成 CycloneDX CBOM。

---

## 10. 附录

### 10.1 术语

| 术语 | 含义 |
|---|---|
| ML-DSA | Module-Lattice-Based Digital Signature Algorithm（FIPS 204） |
| SM2 / SM3 / SM4 | 中国商用密码算法族（椭圆曲线签名 / 哈希 / 分组密码） |
| CBOM | Cryptographic Bill of Materials，密码物料清单 |
| STRIDE | Spoofing/Tampering/Repudiation/Information Disclosure/DoS/Elevation |
| canonical Base64 | 解码后重新编码与原串逐字一致的 Base64 表示 |
| legacy 验签 | 无算法提示时按 `LEGACY_VERIFY_ALGORITHM="SM2"` 回退的只读路径 |

### 10.2 参考资料

- NIST FIPS 204（ML-DSA）：<https://csrc.nist.gov/pubs/fips/204/final>
- NIST FIPS 203（ML-KEM）：<https://csrc.nist.gov/pubs/fips/203/final>
- NIST FIPS 205（SLH-DSA）：<https://csrc.nist.gov/pubs/fips/205/final>
- RFC 4648（Base64）：<https://www.rfc-editor.org/rfc/rfc4648>
- RFC 8998 Appendix A.1（SM4-GCM 已知答案向量）：<https://www.rfc-editor.org/rfc/rfc8998.html#appendix-A.1>
- pqcrypto 1.0.0：<https://pypi.org/project/pqcrypto/1.0.0/>
- gmssl 3.2.2：<https://pypi.org/project/gmssl/3.2.2/>

### 10.3 文档关系与版本

| 文档 | 版本 | 职责 |
|---|---|---|
| `README.md` | 当前 | 使用、配置、迁移说明、测试入口 |
| `CBOM.md` | v2（2026-10-31） | 密码资产清单、迁移状态、尺寸与依赖 |
| `SECURITY_REPORT.md` | v1.0（2026-10-31） | 威胁建模、风险矩阵、测试证据映射 |

**维护约定**：算法、依赖、信任边界或数据库 schema 变更时，同步更新三份文档；威胁编号（`T-*`）与风险编号（`R-*`）保持稳定，新增条目只追加、不复用。
