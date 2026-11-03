"""本机交互演示入口：控制台操作与端到端演示。"""
from pathlib import Path
import argparse
import json
import sys
import uuid

ROOT = Path(__file__).resolve().parent


def show(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def demo():
    from lab.auth import DEMO_PASSWORD
    from lab.context import Context
    from lab.errors import LabError
    from tasks.workflow_tasks import submit_material, handle_approval, read_material
    run_dir = ROOT / "runtime" / "demo_runs" / uuid.uuid4().hex[:12]
    ctx = Context(run_dir)
    student = ctx.auth.login("S001", DEMO_PASSWORD)
    counselor = ctx.auth.login("T017", DEMO_PASSWORD)
    finance = ctx.auth.login("F001", DEMO_PASSWORD)
    other = ctx.auth.login("S002", DEMO_PASSWORD)
    content = (ROOT / "samples" / "application_s001.txt").read_bytes()
    print("演示数据目录：", run_dir)
    print("[1] 学生提交并加密材料")
    show(submit_material(ctx, student, "APP-2026-001", content, "UPLOAD-DEMO-01"))
    manifest, signature = ctx.prepare_approval(counselor, "APP-2026-001", request_id="R103")
    print("[2] 篡改审批决定，必须拒绝")
    altered = dict(manifest, decision="reject")
    try:
        handle_approval(ctx, counselor, altered, signature)
    except LabError as error:
        if error.code != "SIGNATURE_INVALID":
            raise
        print("已拒绝：", error.code)
    else:
        raise AssertionError("篡改请求未被拒绝")
    print("[3] 提交原始有效审批")
    first = handle_approval(ctx, counselor, manifest, signature)
    show(first)
    print("[4] 重复提交，仅返回已有结果")
    repeated = handle_approval(ctx, counselor, manifest, signature)
    assert repeated["replayed"] and repeated["approval_id"] == first["approval_id"]
    assert ctx.store.count("approvals") == 1
    show(repeated)
    print("[5] 其他学生读取，必须在解密前拒绝")
    before = ctx.crypto.calls["open"]
    try:
        read_material(ctx, other, "APP-2026-001", "READ-OTHER")
    except LabError as error:
        if error.code != "FORBIDDEN":
            raise
        assert before == ctx.crypto.calls["open"]
        print("已拒绝：", error.code, "；解密调用增加0次")
    else:
        raise AssertionError("越权读取未被拒绝")
    print("[6] 资助岗位合法读取，原始字节一致")
    assert read_material(ctx, finance, "APP-2026-001", "READ-FINANCE") == content
    print("演示通过。运行run_tests.py可执行全部正常与异常验收。")
    return 0


def console():
    from lab.auth import DEMO_PASSWORD
    from lab.context import Context
    from lab.errors import LabError
    from tasks.workflow_tasks import submit_material, handle_approval, read_material
    ctx = Context(ROOT / "runtime" / "manual")
    principal, last_packet = None, None
    print("奖助学金材料审批与安全归档演示")
    print("演示账号：S001 S002 T017 T018 F001 A001")
    print("本机演示口令：", DEMO_PASSWORD)
    print("材料和状态保存在：", ctx.root)
    while True:
        who = f"{principal.actor_id} / {principal.role}" if principal else "未登录"
        print(f"\n当前：{who}")
        print("1 登录或切换账号  2 申请列表  3 提交材料  4 查看材料")
        print("5 签名并审批      6 重试上次审批  7 审计记录  0 退出")
        choice = input("选择：").strip()
        if choice == "0":
            return 0
        try:
            if choice == "1":
                account = input("账号：").strip()
                # 演示口令公开；input() 兼容常见 IDE 运行控制台。
                password = input("口令（直接回车使用演示口令）：") or DEMO_PASSWORD
                principal = ctx.auth.login(account, password)
                last_packet = None
                print("登录成功")
                continue
            if principal is None:
                print("请先登录")
                continue
            if choice == "2":
                show(ctx.list_applications(principal))
            elif choice == "3":
                app_id = input("申请编号（默认APP-2026-001）：").strip() or "APP-2026-001"
                path = input("本地材料路径（回车使用虚构样例）：").strip().strip('"')
                source = Path(path).expanduser() if path else ROOT / "samples" / "application_s001.txt"
                if source.stat().st_size > 1024*1024:
                    print("材料不能超过1 MB")
                    continue
                result = submit_material(ctx, principal, app_id, source.read_bytes(),
                                         "UP-" + uuid.uuid4().hex)
                show(result)
            elif choice == "4":
                app_id = input("申请编号：").strip()
                content = read_material(ctx, principal, app_id, "READ-" + uuid.uuid4().hex)
                print(f"读取成功，共{len(content)}字节；以下最多显示500个字符。")
                print(content.decode("utf-8", errors="replace")[:500])
                print("未将原文写入服务端文件。")
            elif choice == "5":
                app_id = input("申请编号：").strip()
                decision = input("决定 approve / reject（默认approve）：").strip() or "approve"
                manifest, signature = ctx.prepare_approval(principal, app_id, decision)
                last_packet = (manifest, signature)
                show(handle_approval(ctx, principal, manifest, signature))
            elif choice == "6":
                if last_packet is None:
                    print("当前会话没有已签署的审批请求")
                else:
                    show(handle_approval(ctx, principal, *last_packet))
            elif choice == "7":
                show(ctx.audit_events(principal))
            else:
                print("请输入菜单中的数字")
        except LabError as error:
            print("业务拒绝：", error)
        except (OSError, ValueError) as error:
            print("文件或输入错误：", error)


def main():
    parser = argparse.ArgumentParser(description="奖助学金审批与安全归档演示（国密 + ML-DSA）")
    parser.add_argument("--demo", action="store_true", help="独立目录运行正常和异常演示")
    parser.add_argument("--self-check", action="store_true", help="检查依赖与底层密码")
    parser.add_argument("--test", action="store_true", help="运行全部验收测试")
    args = parser.parse_args()
    try:
        if args.self_check:
            from self_check import main as self_check
            return self_check()
        if args.test:
            from run_tests import run
            return run()
        return demo() if args.demo else console()
    except ImportError as error:
        print("依赖未安装或解释器选择不正确：", error)
        print("请运行 python -m pip install -r requirements.txt")
        return 2


if __name__ == "__main__":
    sys.exit(main())
