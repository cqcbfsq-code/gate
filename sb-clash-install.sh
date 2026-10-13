#!/usr/bin/env bash
# 给 sb-smjm 的本地订阅服务加一个 Clash/mihomo 格式端点：http://<IP>:8199/clash
# 原因：sb-smjm 只产出 nodes.txt（明文链接）+ sub.txt（base64 链接），Clash 系客户端拿不到
#       proxy-groups，导入后节点为 0。这里把同一份 nodes.txt 转成 mihomo YAML 再挂到 webroot。
# 用法：curl -Ls https://raw.githubusercontent.com/cqcbfsq-code/gate/main/sb-clash-install.sh | bash
# 只新增文件，不改 sb-smjm 自己的 nodes.txt / sub.txt，可反复执行。
set -u
SB=/etc/sb-smjm
BIN=/usr/local/bin/sb-clash
[ -d "$SB" ] || { echo "[ERR] 没找到 $SB"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[ERR] 缺 python3"; exit 1; }

cat > "$BIN" <<'PYEOF'
#!/usr/bin/env python3
# nodes.txt（通用链接）-> mihomo YAML -> webroot/clash
import base64, json, os, re, subprocess, urllib.parse as up

SB = "/etc/sb-smjm"
SRC = os.path.join(SB, "nodes.txt")


def dec(v):
    return up.unquote(v)


def conv(line):
    line = line.strip()
    if "://" not in line:
        return None
    t, rest = line.split("://", 1)
    t = t.lower()
    if t == "vmess":
        try:
            d = json.loads(base64.b64decode(rest).decode("utf-8", "ignore"))
        except Exception:
            return None
        p = {"name": d.get("ps") or ("vmess-%s" % d.get("add")), "type": "vmess",
             "uuid": d["id"], "server": d["add"], "port": int(d["port"]),
             "cipher": d.get("scy") or "auto", "alterId": int(d.get("aid") or 0), "udp": True}
        net = (d.get("net") or "tcp").lower()
        if net in ("ws", "websocket"):
            p["network"] = "ws"
            p["ws-opts"] = {"path": d.get("path") or "/", "headers": {"Host": d.get("host") or d["add"]}}
        elif net in ("grpc",):
            p["network"] = "grpc"
            p["grpc-opts"] = {"grpc-service-name": (d.get("path") or "").lstrip("/")}
        if (d.get("tls") or "").lower() in ("tls", "1"):
            p["tls"] = True
            p["servername"] = d.get("sni") or d.get("host") or d["add"]
            p["skip-cert-verify"] = True
        return p
    m = re.match(r"^([a-z0-9]+)://([^@]+)@([^:?/]+):(\d+)(.*)$", line)
    if not m:
        return None
    t, cred, host, port, tail = m.groups()
    q = dict(up.parse_qsl(tail.split("#")[0].lstrip("/?")))
    name = up.unquote(line.split("#", 1)[1]) if "#" in line else host
    p = {"name": name, "type": t, "server": host, "port": int(port), "udp": True}
    if t in ("vless", "trojan"):
        p["uuid" if t == "vless" else "password"] = cred
        p["servername"] = q.get("sni") or host
        if q.get("security") == "tls" or q.get("tls") == "1" or q.get("security") == "reality":
            p["tls"] = True
        if q.get("security") == "reality":
            p["reality-opts"] = {"public-key": q.get("pbk"), "short-id": q.get("sid") or ""}
            p["client-fingerprint"] = q.get("fp") or "chrome"
        if q.get("flow"):
            p["flow"] = q["flow"]
        if q.get("insecure") == "1":
            p["skip-cert-verify"] = True
        net = (q.get("type") or "tcp").lower()
        if net not in ("tcp", "raw"):
            p["network"] = net
        if net == "ws":
            p["ws-opts"] = {"path": dec(q.get("path") or "/"), "headers": {"Host": q.get("host") or ""}}
        if q.get("alpn"):
            p["alpn"] = [q["alpn"]]
    elif t == "ss":
        head = cred
        p["password"] = dec(head.split(":")[-1])
        p["cipher"] = up.unquote(head.split(":")[0]) if ":" in head else "aes-256-gcm"
    elif t == "hysteria2":
        p["password"] = dec(cred)
        p["sni"] = q.get("sni")
        p["skip-cert-verify"] = True
        if q.get("alpn"):
            p["alpn"] = [q["alpn"]]
    elif t == "tuic":
        u, _, pw = cred.partition(":")
        p["username"], p["password"] = u, dec(pw)
        p["congestion_control"] = q.get("congestion_control") or "bbr"
        p["alpn"] = [q.get("alpn") or "h3"]
        p["sni"] = q.get("sni")
        p["skip-cert-verify"] = True
    elif t == "anytls":
        # 关键：anytls 不要写 alpn。链接里那个 alpn=h3 是脚本自己塞的，
        # 带上它 mihomo 会去协商 h3 导致握手失败（实测 h3=503、不写=354ms）。
        p["password"] = dec(cred)
        p["sni"] = q.get("sni")
        p["skip-cert-verify"] = True
    else:
        return None
    return p


def y(v):
    return json.dumps(v, ensure_ascii=False)


def main():
    if not os.path.exists(SRC):
        raise SystemExit("[ERR] 没有 %s" % SRC)
    lines = [l for l in open(SRC, encoding="utf-8", errors="ignore").read().splitlines() if l.strip()]
    proxies, seen = [], set()
    for l in lines:
        p = conv(l)
        if not p or p["name"] in seen:
            continue
        seen.add(p["name"])
        proxies.append(p)
    if not proxies:
        raise SystemExit("[ERR] 没解析出任何节点，保持旧文件不动")
    names = [p["name"] for p in proxies]

    o = []
    o.append("# 由 sb-clash 从 %s 生成，勿手改；重新生成：/usr/local/bin/sb-clash" % SRC)
    o.append("mode: rule")
    o.append("log-level: info")
    o.append("allow-lan: false")
    o.append("ipv6: false")
    o.append("unified-delay: true")
    o.append("tcp-concurrent: true")
    o.append("find-process-mode: off")
    o.append("global-client-fingerprint: chrome")
    o.append("profile:")
    o.append("  store-selected: true")
    o.append("  store-fake-ip: true")
    o.append("dns:")
    o.append("  enable: true")
    o.append("  enhanced-mode: fake-ip")
    o.append("  fake-ip-range: 198.18.0.1/16")
    o.append("  default-nameserver: [223.5.5.5, 119.29.29.29]")
    o.append("  nameserver: [223.5.5.5, 119.29.29.29]")
    o.append("  proxy-server-nameserver: [223.5.5.5, 119.29.29.29]")
    o.append("  fake-ip-filter: ['*.lan', '+.local']")
    o.append("proxies:")
    for p in proxies:
        o.append("  - " + json.dumps(p, ensure_ascii=False))
    o.append("proxy-groups:")
    o.append("  - {name: \"⚡ 自动最快\", type: url-test, url: \"http://www.gstatic.com/generate_204\","
             " expected-status: 204, interval: 120, tolerance: 100, lazy: true, max-backed-nodes: 20,"
             " proxies: [%s]}" % ", ".join(y(n) for n in names))
    o.append("  - {name: \"🚀 节点选择\", type: select, proxies: [%s, %s, DIRECT]}"
             % (y("⚡ 自动最快"), ", ".join(y(n) for n in names)))
    o.append("  - {name: GLOBAL, type: select, proxies: [%s, %s]}"
             % (y("⚡ 自动最快"), y("🚀 节点选择")))
    o.append("  - {name: \"🎯 直连\", type: select, proxies: [DIRECT, REJECT]}")
    o.append("rules:")
    o.append("  - 'DOMAIN-SUFFIX,local,DIRECT'")
    o.append("  - 'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve'")
    o.append("  - 'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve'")
    o.append("  - 'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve'")
    o.append("  - 'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve'")
    o.append('  - "MATCH,🚀 节点选择"')
    text = "\n".join(o) + "\n"

    out = os.path.join(SB, "clash.yaml")
    open(out, "w", encoding="utf-8", newline="\n").write(text)

    # 找 webroot：优先问正在监听 8199 的进程要它的工作目录
    port = "8199"
    try:
        for l in open(os.path.join(SB, "state.env"), encoding="utf-8", errors="ignore"):
            m = re.match(r"^SUB_PORT=\"?(\d+)", l)
            if m:
                port = m.group(1)
    except Exception:
        pass
    web = None
    try:
        ss = subprocess.run(["ss", "-lntpH", "sport = :%s" % port], capture_output=True, text=True, timeout=10).stdout
        pid = re.search(r"pid=(\d+)", ss)
        if pid:
            web = os.path.realpath("/proc/%s/cwd" % pid.group(1))
    except Exception:
        pass
    if not web:
        for c in ["/etc/sb-smjm/web", "/etc/sb-smjm/webroot", "/etc/sb-smjm/www", "/etc/sb-smjm"]:
            if os.path.isdir(c):
                web = c
                break
    if not web:
        raise SystemExit("[ERR] 找不到 webroot，只写了 %s" % out)
    dst = os.path.join(web, "clash")
    open(dst, "w", encoding="utf-8", newline="\n").write(text)
    print("[ok] %d 个节点 -> %s 和 %s" % (len(proxies), out, dst))
    print("[ok] 类型分布: %s" % ", ".join(sorted(set(p["type"] for p in proxies))))
    print("[tip] Clash 系客户端订阅地址：http://<公网IP>:%s/clash" % port)


main()
PYEOF
chmod +x "$BIN"

echo "== 生成一次 =="
"$BIN"

echo "== 加定时（每 30 分钟，跟 sb-merge 一起）=="
if command -v crontab >/dev/null 2>&1; then
  ( crontab -l 2>/dev/null | grep -v 'sb-clash'; \
    echo '*/30 * * * * /usr/local/bin/sb-clash >> /var/log/sb-clash.log 2>&1' ) | crontab -
  crontab -l | grep -E 'sb-clash|sb-merge' || true
else
  echo "[WARN] 无 crontab，请手动跑 $BIN"
fi

echo "== 自检：本机 /clash 是否可取 =="
curl -fsS --max-time 15 "http://127.0.0.1:8199/clash" -o /tmp/clash.check && \
  echo "长度 $(wc -c </tmp/clash.check) 字节，proxies $(grep -c '^  - {' /tmp/clash.check) 行" || echo "[WARN] 本机取 /clash 失败"

echo "== 顺带看端口监听（判断 TUIC/AnyTLS 到底起没起）=="
ss -lntup 2>/dev/null | grep -E ':(8443|8444|8445)\b' || echo "(ss 没权限或没监听)"
