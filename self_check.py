"""验证依赖、算法已知答案和 GCM 篡改拒绝，不依赖业务演示数据。"""
import sys


def _check_ml_dsa():
    """pqcrypto 依赖与 ML-DSA 适配器的一次往返验签。"""
    import pqcrypto
    from lab.signers import get_signer
    signer = get_signer("ML-DSA-65")
    private, public = signer.generate_keypair()
    signature = signer.sign(private, b"self-check", context=b"aid-approval-v1")
    assert signer.verify(public, b"self-check", signature, context=b"aid-approval-v1")
    print("pqcrypto:", pqcrypto.__version__)
    print(f"ML-DSA-65: 公钥 {signer.public_key_bytes} B，签名 {signer.signature_bytes} B，往返验签通过")


def main():
    try:
        import cryptography
        import gmssl
        from run_tests import run
        print("Python:", sys.version.split()[0])
        print("cryptography:", cryptography.__version__)
        print("gmssl:", gmssl.__file__)
        _check_ml_dsa()
        print("执行底层密码自检。业务演示数据不影响本项。\n")
        return run("test_crypto.py", report=False)
    except ImportError as exc:
        print("依赖未安装：", exc)
        print("请在项目根目录运行：")
        print("python -m pip install -r requirements.txt")
        return 2


if __name__ == "__main__":
    sys.exit(main())
