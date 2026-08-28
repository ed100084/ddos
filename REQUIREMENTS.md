# ddos-tool — Requirements & Handoff Doc

> 給接手開發的 AI / engineer。這份文件**自足**:不需要讀 git log 或聊天記錄就能繼續做。
> 最後更新:2026-08-28(對應 commit `8c2045c` + `--json`)。

## 1. 專案定位

Python 的 **DDoS 模擬器 / Flood Generator** — 用來壓測自家入口(WAF、CDN、防火牆)扛不扛得住。**不是**偵測系統,也**不是**真實攻擊武器(單機 ~10–50k pps)。

| 類型 | 本專案? |
|---|---|
| A. Flood Generator(攻擊模擬)| ✅ |
| B. Detection / Mitigation | ❌ |
| C. 分散式 botnet 武器 | ⏳ 長期 |

## 2. 目前狀態(已驗證,別重測)

### 引擎

| 引擎 | 狀態 | 備註 |
|---|---|---|
| L7 HTTP flood(asyncio + aiohttp)| ✅ | keep-alive workers |
| L4 UDP flood | ✅ | **已知瓶頸**:每 packet 開/關一次 datagram endpoint,高 pps 時要改成 per-worker 長存 transport(見 R6)|
| L4 TCP connect flood | ✅ | 可多 port round-robin;SYN-ACK 就算 ok(即使對方馬上 RST)|
| SYN flood(scapy)| 🚧 stub | lazy import,需 root / `CAP_NET_RAW`(見 R1)|

### 其他能力

- **CLI**:`ddos run -c cfg.yaml [--duration] [--rps] [--ramp-start/--ramp-end/--ramp-steps] [--json] [-q]`
- **Ramp-up**:分階段調 token bucket rate(不重啟 engine、keep-alive 不斷),per-step 表顯示哪一級開始壞
- **`ddos probe <host> -p 1-65535`**:async TCP connect scanner,分類 open / closed(RST@SYN)/ filtered(timeout)+ RST-after-data 偵測
- **Config**:YAML + pydantic v2(`src/ddos_tool/config.py`)
- **Metrics**:live pps ticker(stderr)+ end summary(stdout);`--json` 時 stdout 純 JSON(header/ticker 走 stderr)
- **Tests**:25 passed,pytest,**不用 pytest-asyncio**(測試自己 `asyncio.run()`,保持依賴最小)

### 目標機實測事實(2026-08-28,別重新推論)

Target:`203.0.113.17`(placeholder;真 IP 在 gitignored 的 `config/local.yaml`,China Telecom / Chongqing,RTT ~60ms)。從 toolap01(`10.6.4.39`)走實體網卡直連,**不經 Tailscale**。

- 全 port scan:**只有 :80 / :1720(RTP)/ :3128(proxy)/ :8080** 接受 SYN,其餘 RST@SYN
- 這 4 個 port **idle ~0.1–0.5s 就 RST、零 banner** → 前面是 **stateful firewall / NAT appliance**(疑似 VPN concentrator 邊界),不是真 web service
- UDP 全無 echo(1720/80/5060/500)→ port-forward rule 存在但後端沒 daemon
- **瓶頸 = 同時連線數,不是頻寬**:3000 rps @ 64 workers = 0% err;同 rate @ 300 workers = 85% err;ramp 到 ~6000 rps(step 6)開始大量 RST
- 對策方向(給報告用):SYN cookies / connection-table sizing,不是加頻寬

## 3. 架構 & 慣例(改碼前先看)

```
ddos/
├── pyproject.toml          # setuptools, src layout; deps: aiohttp/click/pydantic/PyYAML; dev: pytest
├── config/example.yaml     # 本地 dev server 用
├── config/example-target.yaml  # placeholder target(203.0.113.x TEST-NET,可公開)
#   config/local.yaml           # ⚠️ 真目標 IP(gitignored,別 commit)
├── scripts/dev_server.py   # 本地 target:aiohttp counter + UDP sink
├── src/ddos_tool/
│   ├── cli.py              # click group: run / probe;_ramp_controller 在這裡
│   ├── config.py           # pydantic models: Config/Rate/Ramp/HttpPayload/UdpPayload/TcpPayload
│   ├── engine/base.py      # AttackEngine ABC + TokenBucket(有 set_rate() 供 ramp)
│   ├── engine/http_flood.py / udp_flood.py / tcp_flood.py / syn_flood.py
│   ├── metrics.py          # Metrics(live ticker)+ summarize()
│   ├── probe.py            # TCP connect scanner(scan/format_report/PortResult)
│   └── reporter.py         # build_result()(JSON dict)+ report(human/JSON 輸出)
└── tests/                  # test_config / test_http_flood / test_tcp_flood / test_probe / test_ramp / test_reporter
```

**慣例(照做,別自創)**:
- Python ≥3.10,`from __future__ import annotations`;type hints 用 `X | None`
- engine 一律繼承 `AttackEngine`,實作 `async run()`,填 `self.stats = {"sent","ok","err"}`;rate 從 `cfg.effective_rps()` 取(ramp 時是 start)
- **測試自包含**:不用 pytest-asyncio、不用 async fixture,直接 `async def go(): ...` + `asyncio.run(go())`;port 用 81xx–84xx 段避免撞 dev_server(8099/9999)
- commit:conventional commits(`feat:` / `fix:` / `config:` / `docs:`),**每個功能做完就 commit + push**(origin = https://github.com/ed100084/ddos.git,branch main)
- 驗證流程:`.venv/bin/python -m pytest -q` → 對 dev_server 或真目標 smoke test → commit → push
- venv 在 `.venv`(Debian 沒 ensurepip,是用 get-pip.py 灌的;重建:`python3 -m venv --without-pip .venv && .venv/bin/python /tmp/get-pip.py`)

## 4. Requirements Backlog(依優先序)

> 每項有 **acceptance criteria**;做完一項就 commit+push,別一次吞太多。
> P0 = 先做,P1 = 次之,P2 = 有空再做。

### R1 (P0)— SYN flood engine 正式化
`syn_flood.py` 目前是 stub(scapy lazy import、fire-and-forget)。
- [ ] `pip install scapy` 做成 optional extra:`[project.optional-dependencies] syn = ["scapy>=2.11"]`,README 標明
- [ ] 支援 **source IP spoofing**(可選):隨機 / CIDR range,需 root + `rp_filter=2`;config 加 `syn: { spoof_src: "10.0.0.0/8" | random }`
- [ ] stats 區分 `sent`(SYN 發出)與 `acked`(收到 SYN-ACK,用 sniff 或 raw socket 回讀)— MVP 可先只記 sent
- **AC**:`ddos run -c cfg.yaml --rps 2000`(attack: syn)對 dev_server 跑 10s,sent ≈ 20k ±15%;`pytest` 全綠(scapy 沒裝時 `test_syn_flood.py` 要 skip,不能 fail)

### R2 (P0)— Auto breaking-point(`--find-limit`)
現在 ramp 是固定 end_rps;要做「跑到壞為止」。
- [ ] CLI:`ddos run -c cfg.yaml --ramp-start 500 --ramp-steps 10 --find-limit --err-threshold 5`(%)
- [ ] 行為:每 step 結束算該 step err%,**連續 2 個 step ≥ threshold 就停**;輸出 `breaking_rps`(最後一個 < threshold 的 rate)進 summary + JSON(`result["breaking_rps"]`)
- [ ] 可選 `--max-rps` 上限防跑爆
- **AC**:對 dev_server(本地,幾乎不會壞)跑到 max;對真目標應停在 ~5000–6000 rps 附近;JSON 有 `breaking_rps` 欄位

### R3 (P1)— Prometheus metrics endpoint
現在只有 stdout。要能接 Grafana。
- [ ] optional extra `[metrics] = ["prometheus-client>=0.20"]`;CLI flag `--prom-port 9464`(預設關)
- [ ] counters:`ddos_sent_total{attack,target}`、`ddos_ok_total`、`ddos_err_total`、gauge `ddos_current_rate`、`ddos_inflight`(= workers 中正在等 op 的數)
- [ ] run 結束時 endpoint 多留 5s 再關(讓 scrape 抓到最後一筆)
- **AC**:`curl localhost:9464/metrics` 在 run 期間有上述 metrics;不裝 prometheus-client 時 `--prom-port` 給清楚的 error

### R4 (P1)— pcap replay engine
用真實流量回放,比合成 payload 更貼近。
- [ ] optional extra `[replay] = ["dpkt>=1.9"]`(或 scapy rdpcap);新 attack type `replay`
- [ ] config:`replay: { file: "capture.pcap", rate_factor: 2.0 }`(2x 速度回放)
- [ ] 保留原 packet 的 src/dst/port/payload;可選 `--randomize-src-port`
- **AC**:對 dev_server 放一個 1s pcap,rate_factor=1 → sent ≈ pcap 內 packet 數 ±10%

### R5 (P1)— UDP engine 效能優化(已知瓶頸)
現在每 packet `create_datagram_endpoint` + close,高 pps 時是主要開銷。
- [ ] 改成 **per-worker 長存 transport**(worker 開始時建、結束時關),payload 只 `sendto()`
- [ ] 目標:單機 UDP ≥ 50k pps @ 64 workers(目前 ~16–20k)
- **AC**:對 dev_server UDP sink,`--rps 50000 --duration 10`,avg rate ≥ 45k 且 err < 2%;既有 test 不壞

### R6 (P2)— Payload / source randomization
- [ ] `http: { body_template: "...{rand_int}...", headers_random: [...] }`、`udp: { fill: "random" | "x" }`
- [ ] TCP connect flood 可選 **random src port**(要 raw socket,或接受 OS 分配)
- **AC**:同一 run 內抓 pcap(或用 dev_server 記 payload),確認有變化

### R7 (P2)— `ddos probe` → config 自動串接
- [ ] `ddos probe <host> --emit-config out.yaml`:掃完直接產一份 target yaml(open ports 填進 tcp.ports / udp target)
- **AC**:對真目標跑,產出的 yaml 直接 `ddos run -c` 能跑

### R8 (P2)— CI(GitHub Actions)
- [ ] `.github/workflows/ci.yml`:matrix python 3.10/3.12 → `pip install -e ".[dev]"` → `pytest`;push + PR 觸發
- **AC**:PR 上能看到綠勾;本地沒 scapy/prometheus 時 optional extras 不影響 CI

### R9 (P2)— 分散式 workers(botnet-like)
- [ ] Redis queue:controller 發 op token,workers(多台)領 token 發包;`--workers remote:N`
- **AC**:兩台機器合計 pps ≈ 單機 ×1.8(留 10% overhead)

## 5. 已知限制 / 誠實定位

- Python 單機天花板:HTTP ~數萬 req/s、UDP 優化後 ~50k pps — 是**模擬器**,不是 Tbps 武器
- raw socket(SYN/spoofing)要 root 或 `CAP_NET_RAW`;spoofing 還要關 `rp_filter`
- 打非自己的 target = 法務問題(醫療環境的鄰居可能是病歷系統)— README 有寫
- backpressure:目標 drop 時 sender 變瓶頸,stats 已分 sent/ok/err

## 6. 快速上手(接手第一天)

```bash
cd ddos
python3 -m venv --without-pip .venv && curl -sSL https://bootstrap.pypa.io/get-pip.py | .venv/bin/python
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q                 # 25 passed
.venv/bin/python scripts/dev_server.py &      # 本地 target :8099 / :9999
.venv/bin/ddos run -c config/example.yaml --duration 3 --rps 2000
.venv/bin/ddos probe 127.0.0.1 -p 1-100      # scanner
```
