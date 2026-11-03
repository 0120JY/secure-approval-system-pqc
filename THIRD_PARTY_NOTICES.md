# 第三方依赖与测试资料

项目通过 pip 安装以下依赖，未将第三方密码库源码改写或内联进本仓库。

| 依赖 | 版本 | 关系 | 上游与许可 |
|---|---|---|---|
| gmssl | 3.2.2 | 直接依赖 | https://pypi.org/project/gmssl/3.2.2/ BSD |
| cryptography | 46.0.3 | 直接依赖 | https://github.com/pyca/cryptography Apache-2.0 OR BSD-3-Clause |
| pqcrypto | 1.0.0 | 直接依赖 | https://pypi.org/project/pqcrypto/1.0.0/ Apache-2.0 |
| pycryptodomex | 3.24.1 | gmssl 的传递依赖 | https://www.pycryptodome.org/ BSD, Public Domain |
| cffi | 2.1.1 | cryptography 的传递依赖 | https://pypi.org/project/cffi/ MIT-0 |
| pycparser | 3.11 | cffi 的传递依赖 | https://pypi.org/project/pycparser/ BSD-3-Clause |

测试中的 SM4-GCM 向量来自 RFC 8998 Appendix A.1。SM2、SM3 与单分组 SM4 测试使用公开的固定示例值，这些测试值仅用于自检。演示运行时的材料密钥、签名私钥、签名临时随机数及 Nonce 由 secrets 重新生成。
