# gate — VPN Gate 家宽节点自动筛选

VPN Gate 目录 → 只保留 SSTP(TCP) 入口 → 调 Cloudflare 检测 Worker 逐个真拨 → 输出
`public/nodes.txt`（链式节点行：`入口:443#国家-住宅-NN$sstp://vpn:vpn@中继:端口`）
+ `public/data.json` + 静态看板，由 GitHub Pages 发布。

与上游教程的差别（都是实测出来的，不是猜的）：

- `ONLY_RESIDENTIAL=1`（默认）：只输出住宅出口，机房出口直接丢掉——面板只要家宽。
- `PER_COUNTRY=6`（默认）：每国最多 6 行，避免订阅里塞进上百个死节点。
- 入口域名池是固定的 6 个（`EDGE_HOSTS`）。教程第 2 步让你填的 `OPTIMAL_API`
  （`cf.090227.xyz/ct|cu|cmcc`）我实测过：拿电信优选 IP 当链式入口，
  231/235/259 ms（域名入口）对 810/814/829 ms（IP 入口）——**慢约 570 ms**，
  因为那批 IP 指向 SJC 美西 PoP，而我们的域名从中国解析到近端 PoP。所以这里不接。
- 检测端点部署在同一账号的 **Pages**（`gatecheck-deo.pages.dev`），不是 Workers：
  这个账号的 Workers 现在每个请求都回 `error code: 1101`（连 3 行 hello-world 都一样），
  Pages Functions 正常，且 Pages 版在中国可直连。
- 不发布 `sub.txt`：明文 `vless://<UUID>@<域名>` 的路径就是按那个 UUID 异或出来的，
  公开等于送节点凭据。

定时：`cron: "0 */2 * * *"`；GitHub Actions 实际会被压到 2–8 小时一次，别指望 30 分钟。
