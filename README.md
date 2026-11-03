# Secure Approval System

> 密码敏捷的奖助学金材料审批与安全归档参考实现：SM3 / SM4-GCM 保障完整性与静态加密，FIPS 204 **ML-DSA-65** 作为默认审批签名算法，历史 SM2 数据保留只读验签能力。

**核心文档：** [CBOM 密码物料清单](CBOM.md) · [安全威胁建模报告](SECURITY_REPORT.md) · [第三方依赖声明](THIRD_PARTY_NOTICES.md)

## 项目简介

本参考实现完成“学生提交材料 → 辅导员签名审批 → 受控解密读取 → 审计留痕”的完整闭环：审批签名默认使用后量子算法 **ML-DSA-65**（历史 SM2 签名只读兼容），SM3 保障材料与请求完整性，SM4-GCM 保障材料静态加密。

底层架构升级分两步完成：先把与 SM2 强绑定的密码调用改造成**算法可插拔、编码可兼容、旧数据可平滑迁移**的密码敏捷架构；随后接入 FIPS 204 **ML-DSA-65** 并切换为系统默认签名算法。50 项既有回归测试保持未修改并全部通过，同时新增 22 项安全回归测试（13 项密码敏捷性 + 9 项 ML-DSA）。

## 核心改造点

### 1. 编码升级：废弃定长 Hex，统一标准 Base64

**改造前**：公钥与签名被 `HEX128` 硬性限定为 128 个十六进制字符（64 字节），这是 SM2 的尺寸假设。

**改造后**：公钥与签名统一使用 **RFC 4648 标准 Base64 + `=` padding**，长度由算法插件自行声明，业务层不再假设固定尺寸。

| 对象 | Hex | Base64 | 体积节省 |
|---|---:|---:|---:|
| SM2 签名（64 B） | 128 字符 | 88 字符 | 31% |
| ML-DSA-65 公钥（1,952 B） | 3,904 字符 | 2,604 字符 | 33% |
| ML-DSA-65 签名（3,309 B） | 6,618 字符 | 4,412 字符 | 33% |

编码层实现 `b64_to_bytes_strict()`，执行三项严格校验：

1. **字母表**：只接受标准 Base64（`+/`），拒绝 Base64URL、空白、换行；
2. **Padding**：长度与 `=` 必须完全匹配，拒绝缺失或多余填充；
3. **规范形式（canonical）**：解码后重新编码必须与原字符串逐字一致，拒绝 `AB==` 这类“尾部无关比特不同但解码结果相同”的非规范表示。

> 为什么这和安全有关：同一段签名字节如果存在多种字符串表示，幂等去重、审计检索和签名比对都会出现歧义。规范化编码让“同一字节序列 = 同一字符串”成为可验证的不变量，是可靠重放检测与请求去重的前提。Base64 本身不是加密，也不单独阻止重放；重放防护仍由 `request_id` + 规范化清单指纹负责。

### 2. 接口解耦：抽象 Signer 接口，接入 PQC 的“万能插座”

**改造前**：业务代码通过 `Crypto` 直接触达 `gmssl`，SM2 的 `r||s` 编码、64 字节长度、曲线点校验散落在加密适配器中。

**改造后**：新增 `lab/signers.py`，以抽象基类定义签名算法契约，采用**策略模式 + 依赖倒置**：

```text
tasks/  ──依赖──▶  Crypto  ──委托──▶  Signer (ABC)
                                        ├── SM2Signer        （旧数据只读兼容）
                                        ├── MLDSASigner      （当前默认，FIPS 204）
                                        └── HybridSigner     （预留，未实现）
```

```python
class Signer(ABC):
    alg_id: str              # "SM2" / "ML-DSA-65"
    public_key_bytes: int
    signature_bytes: int
    quantum_resistant: bool  # ML-DSA 为 True
    private_key_encoding     # SM2 为 hex，ML-DSA 为 base64

    def generate_keypair(self): ...        # -> (private_key, public_key)
    def sign(self, private_key, data, context=None): ...
    def verify(self, public_key, data, signature, context=None): ...
    def validate_public_key(self, public_key): ...
    def normalize_public_key(self, value, encoding=None): ...  # 编码内聚到算法
```

业务层只依赖契约，不依赖具体算法；算法通过注册表 `SIGNERS`（工厂）解析，未知算法抛出 `UNSUPPORTED_ALGORITHM`。`MLDSASigner` 已实现并注册，默认算法切换为 ML-DSA-65 后，审批、授权、事务与审计代码**零改动**。

### 3. 消除硬编码：从魔法值到配置驱动

| 改造前 | 改造后 |
|---|---|
| `HEX128 = re.compile(r"[0-9a-fA-F]{128}\Z")` 作为准入校验 | 定长校验不再参与业务准入；仅在历史 Hex 识别中保留 |
| `signing_key_id = f"{actor_id}-SM2-01"` | `config.key_id_for(actor_id)`，模板默认 `{actor_id}-{algorithm}-01` |
| 算法隐含在调用点 | `AID_SIGNING_ALGORITHM` / JSON 配置显式声明 |
| 新增算法需改业务代码 | 新增 `Signer` 子类并注册即可 |

默认算法切换为 ML-DSA-65 后，默认模板产出 `T017-ML-DSA-65-01`；历史 SM2 密钥仍以 `T017-SM2-01` 留存并只读兼容。密钥标识始终由模板 `{actor_id}-{algorithm}-01` 决定。

### 4. 数据库平滑迁移：新写 Base64，旧 Hex 只读兼容

| 表 | 新增列 | 默认值 | 用途 |
|---|---|---|---|
| `public_keys` | `alg`、`encoding` | `SM2`、`hex` | 记录可信公钥的算法与编码 |
| `approvals` | `sig_alg`、`sig_encoding` | `SM2`、`hex` | 记录审批签名的算法与编码 |
| `signing_keys`（密钥库） | `alg` | `SM2` | 签名密钥与算法绑定 |

迁移策略：

- 打开数据库时用 `PRAGMA table_info` 检测缺列，自动执行 `ALTER TABLE ... ADD COLUMN`，旧库可直接启动；
- **新写入固定 Base64**（`config.WRITE_ENCODING = "base64"`），不提供写 Hex 的开关；
- **旧行保持 `hex` 默认值、只读兼容**，验签时按该行记录的 `encoding` 解码；
- 无编码提示的旧调用按“Base64 优先、Hex 回退”处理；无算法提示的验签默认走 `LEGACY_VERIFY_ALGORITHM = "SM2"`，与“新数据默认 ML-DSA”互不影响；
- 密钥库 `signing_keys` 去掉 `owner_id` 的 UNIQUE 约束，同一主体可同时持有 SM2 与 ML-DSA 密钥（旧库平滑重建迁移）。

## 安全设计考量

### 算法混淆（Algorithm Confusion）

**威胁**：攻击者诱导系统使用错误或更弱的算法验签（类似 JWT `alg=none`），或系统根据输入长度/前缀猜测算法。

**本系统的处理**：

- 算法**不从请求推断**，而是通过 `signing_key_id` 查服务端可信登记表，取该密钥登记时绑定的 `alg`；
- 未登记或未实现的算法直接抛 `UNSUPPORTED_ALGORITHM`，不会回退到默认算法；
- 密钥所有者必须与登录主体、清单中的 `approver_id` 一致，否则 `IDENTITY_MISMATCH`；
- 验签使用登记表中与该密钥绑定的算法，签名方与验签方不会各自“猜”出不同算法；
- 不提供“按 128 字符就当作 SM2”的隐式路径。

**明确的取舍**：审批清单 `aid-approval-v1` 的 10 个字段中**不含 `sig_alg`**，算法通过 `signing_key_id → public_keys.alg` 绑定。同一主体现可同时登记 SM2 与 ML-DSA 密钥（`signing_keys.owner_id` 已去 UNIQUE），算法仍由 key_id 唯一确定；若未来需要**混合签名**（一个清单同时要求 SM2 + ML-DSA 都验过），应升级为 `aid-approval-v2` 并显式携带 `sig_alg` 与 `key_version`。

### 跨协议攻击（Cross-Protocol / Domain Separation）

**威胁**：把在 A 协议中产生的合法签名，重放/挪用到 B 协议。

**当前防护**：

- 签名输入是**规范化 JSON 清单**（`sort_keys=True`、紧凑分隔符、UTF-8），字段集合固定为 10 个，多一个、少一个、类型不符都会被拒绝；
- 清单内包含 `schema = "aid-approval-v1"`，该值参与签名字节，因此签名被绑定到审批协议域；
- 幂等指纹同样是规范化清单的 SM3，与随机签名值无关。

**预留扩展**：`Signer.sign/verify` 已带可选 `context` 参数，ML-DSA 直接透传给 FIPS 204 的 ctx 做域分离（`self_check.py` 已用 `aid-approval-v1` 验证）。业务层当前仍以清单 `schema` 字段承担域分离，`aid-approval-v2` 将正式启用 context。

### 编码规范化与降级面控制

- 严格 Base64 解码，拒绝非规范形式（见“编码升级”）；
- 新数据不落 Hex，旧 Hex 兼容是**逐行、只读**的，不存在全局“允许 Hex”开关，便于按保留期逐步退役；
- 解密与验签失败一律返回明确的业务错误码，不返回空字节或部分结果伪成功；
- 审批记录、幂等记录、成功审计在同一 SQLite 写事务中提交；拒绝事件在事务回滚后单独写入，避免日志随事务消失。

## 测试保障

```bash
# 在项目根目录执行全部测试
python run_tests.py

# 或运行单个测试模块
python -m unittest tests.test_crypto_agility -v
```

> 测试应通过 `python -m unittest` 或 `run_tests.py` 运行，以确保项目根目录进入 `sys.path`。

> `run_tests.py` 在导入时会把 `AID_SIGNING_ALGORITHM` 钉为 `SM2`：既有 50 个用例 + 密码敏捷性回归以 SM2 世界为断言基准（硬编码 `T017-SM2-01`、Hex 签名），而系统默认已切换为 ML-DSA-65。ML-DSA 行为由 `tests/test_ml_dsa.py` 显式覆盖；显式设置 `AID_SIGNING_ALGORITHM` 可覆盖该钉住值。

**结果：72 项测试全部通过，退出码 0。**

| 测试集 | 数量 | 状态 | 说明 |
|---|---:|---|---|
| 既有回归测试（`test_crypto` / `test_tasks` / `test_workflow`） | 50 | ✅ 全部通过 | **保持未修改**，验证改造未破坏既有行为 |
| 密码敏捷性测试（`tests/test_crypto_agility.py`） | 13 | ✅ 全部通过 | Base64 规范编码、算法注册表、旧数据兼容、迁移 |
| ML-DSA 测试（`tests/test_ml_dsa.py`） | 9 | ✅ 全部通过 | 参数集注册、Base64 往返、context 域分离、SM2/ML-DSA 共存 |

新增的 13 项测试覆盖：

| 类别 | 数量 | 关键断言 |
|---|---:|---|
| Base64 规范编码 | 3 | 标准字母表与 padding；拒绝非规范尾部比特、缺失 padding、空白、URL-safe、多余填充；签名往返与篡改拒绝 |
| Signer 接口与算法注册表 | 3 | 未注册算法抛 `UNSUPPORTED_ALGORITHM`；**不按长度推断算法**；SM2Signer 只接受 Base64 |
| 旧数据与迁移兼容 | 3 | 历史 Hex 公钥/签名无提示可验签；旧 `public_keys`/`approvals` schema 自动补列；旧密钥库补 `alg` |
| 业务集成 | 3 | 新公钥登记为 `SM2/base64`；审批记录写入 `sig_alg`/`sig_encoding`；算法经 `signing_key_id` 绑定而非清单字段 |
| 配置稳定性 | 1 | 密钥模板由算法参数驱动：SM2 产出 `T017-SM2-01`、ML-DSA-65 产出 `T017-ML-DSA-65-01` |

既有测试未做任何修改，避免通过修改断言使测试通过。新增测试使用独立临时目录，不依赖手工菜单数据。

新增的 9 项 ML-DSA 测试覆盖：

| 类别 | 数量 | 关键断言 |
|---|---:|---|
| MLDSASigner 能力 | 2 | ML-DSA-65 往返与篡改拒绝；44/65/87 三参数集尺寸（pk/sk/sig） |
| 尺寸互斥 | 1 | SM2 的 64 字节公钥/签名不被当作合法 ML-DSA 输入 |
| context 域分离 | 1 | 同一消息不同 context 验签失败；缺 context 也失败 |
| 旧数据只读兼容 | 1 | 默认已切 ML-DSA-65 时，无提示 Hex SM2 仍可验签 |
| 密钥共存与迁移 | 2 | 同一主体 SM2/ML-DSA 密钥共存；旧 UNIQUE schema 平滑迁移为多密钥 |
| 端到端审批 | 2 | ML-DSA-65 审批闭环；篡改清单被 `SIGNATURE_INVALID` 拒绝 |

## 架构与目录

```text
┌─────────────┐   ┌──────────────────┐   ┌─────────────────┐
│   tasks/    │──▶│      lab/        │──▶│  lab/signers.py │
│ 业务与事务   │   │ Crypto / Store   │   │ Signer 契约      │
└─────────────┘   │ Config / Audit   │   │  ├ SM2Signer    │
                  └──────────────────┘   │  ├ MLDSASigner  │
                                         │  └ HybridSigner │
                                         └─────────────────┘
```

| 路径 | 内容 |
|---|---|
| `main.py` | 命令行入口、交互式控制台与端到端演示 |
| `tasks/` | 材料摘要、清单规范化、授权、提交、审批、读取 |
| `lab/signers.py` | `Signer` 抽象接口、`SM2Signer`、`MLDSASigner`、算法注册表 |
| `lab/config.py` | 签名算法、密钥标识模板、写编码策略 |
| `lab/crypto_encoding.py` | Base64 / Hex 严格编解码与规范形式校验 |
| `lab/crypto.py` | SM2/SM3/SM4-GCM 适配器与软件密钥库 |
| `lab/store.py` | SQLite 事务、schema 迁移、幂等与审计 |
| `lab/context.py` | 认证、装配、审批材料准备 |
| `tests/` | 72 项测试（50 既有 + 13 敏捷性 + 9 ML-DSA） |
| `CBOM.md` | 密码资产测绘（CBOM v2）、迁移状态与 PQC 剩余风险 |
| `SECURITY_REPORT.md` | 安全威胁建模报告（STRIDE、风险矩阵、测试证据映射） |
| `samples/` | 两份虚构附件 |
| `runtime/` | 运行时自动生成（已忽略）：业务库、密钥库、演示与测试产物 |

## 快速开始

```bash
python -m pip install -r requirements.txt
python self_check.py          # 底层密码自检
python main.py --demo         # 端到端演示（提交/篡改拒绝/审批/重放/越权/读取）
python run_tests.py           # 全部 72 项测试
python main.py                # 交互式控制台
```

> `pycryptodomex` 是 `gmssl` 的传递依赖，`cffi` / `pycparser` 是 `cryptography` 的传递依赖；三者均在 `requirements.txt` 中显式固定版本，以保证可复现安装。

演示账号：`S001` `S002` `T017` `T018` `F001` `A001`，演示口令均为 `Lab2026!`。

## 配置

配置在模块导入时读取一次，需在启动进程前设置；也可用 `AID_CRYPTO_CONFIG` 指向 JSON 文件。

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `AID_SIGNING_ALGORITHM` | `ML-DSA-65` | 新密钥/新签名默认算法，须存在于 `SIGNERS` |
| `AID_LEGACY_VERIFY_ALGORITHM` | `SM2` | 无算法提示验签的回退算法（历史 SM2 只读兼容） |
| `AID_SIGNING_KEY_ID_TEMPLATE` | `{actor_id}-{algorithm}-01` | 密钥标识模板 |
| `AID_ALLOWED_SIGNING_ALGORITHMS` | `SM2,ML-DSA-44,ML-DSA-65,ML-DSA-87` | 预留项，尚未接入强制校验；实际可用算法由注册表决定 |
| `AID_CRYPTO_CONFIG` | 空 | JSON 路径，可覆盖 `signing_algorithm`、`legacy_verify_algorithm`、`key_id_template`、`allowed_signing_algorithms` |

示例：

```bash
AID_SIGNING_KEY_ID_TEMPLATE='{actor_id}.{algorithm}.v1' python run_tests.py
```

## PQC 迁移路线

1. **已完成**：编码 Base64 化、`Signer` 接口、配置化、schema 迁移、旧数据兼容。
2. **已完成**：`MLDSASigner`（FIPS 204，44/65/87）实现并注册，系统默认签名切换为 ML-DSA-65，历史 SM2 只读兼容。
3. **混合签名**：`HybridSigner([SM2Signer(), MLDSASigner()])`，两者都验证通过才接受（本次按“直接替换、旧数据只读兼容”暂缓，预留接口）。
4. **协议升级**：`aid-approval-v2` 显式携带 `sig_alg`、`key_version`、context string。
5. **密钥保护**：私钥迁往 HSM/KMS，建立轮换与吊销生命周期。
6. **退役旧格式**：按数据保留期停止接受 Hex 只读兼容。

详细的资产清单、迁移状态与算法尺寸评估见 [`CBOM.md`](CBOM.md)；威胁场景、残余风险与测试证据映射见 [`SECURITY_REPORT.md`](SECURITY_REPORT.md)。

## 已知边界

这是单机参考实现，复用到生产前需要处理：

- 固定演示口令 `Lab2026!` 且会在控制台打印；会话仅存于进程内存；
- 私钥以明文存于本地 SQLite（目录 `0700`、文件 `0600`），无 HSM/KMS；
- 无 CA、证书链、可信时间戳、网络 TLS、登录限速与密钥轮换界面；
- `gmssl 3.2.2` 为纯 Python 实现、使用私有 `_kg` 且非恒定时间；
- `AID_ALLOWED_SIGNING_ALGORITHMS` 尚未接入强制校验；
- `Signer.sign/verify` 已带 `context` 参数（ML-DSA 可用），但业务层尚未启用，当前域分离依赖清单 `schema` 字段；
- `pqcrypto` 为 Rust/PyO3 扩展（Windows `cp39-abi3` 轮子），非 FIPS 140 认证模块；ML-DSA 私钥仍以明文存于本地 SQLite。

## 技术资料

- gmssl 3.2.2：<https://pypi.org/project/gmssl/3.2.2/>
- cryptography 46.0.3 对称密码：<https://cryptography.io/en/46.0.3/hazmat/primitives/symmetric-encryption/>
- RFC 8998 Appendix A.1（SM4-GCM 已知答案向量）：<https://www.rfc-editor.org/rfc/rfc8998.html#appendix-A.1>
- NIST FIPS 204（ML-DSA）：<https://csrc.nist.gov/pubs/fips/204/final>
- NIST FIPS 205（SLH-DSA）：<https://csrc.nist.gov/pubs/fips/205/final>
- pqcrypto 1.0.0（Rust/PyO3 实现的 ML-DSA）：<https://pypi.org/project/pqcrypto/1.0.0/>

## 许可证

本项目采用 Apache-2.0 许可证，许可证文本见仓库根目录的 `LICENSE`。
