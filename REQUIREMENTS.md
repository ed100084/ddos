# ddos-tool — Requirements & Handoff Doc

> 給接手開發的 AI / engineer。這份文件**自足**:不需要讀 git log 或聊天記錄就能繼續做。
> 最後更新:2026-08-28（對應目前 `main` 的 JSON/reporting 完成版本）。

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
| L4 UDP flood | ✅ | per-worker 長存 transport |
| L4 TCP connect flood | ✅ | 可多 port round-robin;SYN-ACK 就算 ok(即使對方馬上 RST)|
| SYN flood(scapy)| 🚧 stub | lazy import,需 root / `CAP_NET_RAW`(見 R1); spoofing 已改為 opt-in |

### 其他能力

- **CLI**:`ddos run -c cfg.yaml [--duration] [--rps] [--ramp-start/--ramp-end/--ramp-steps] [--json] [-q]`
- **Ramp-up**:分階段調 token bucket rate(不重啟 engine、keep-alive 不斷),per-step 表顯示哪一級開始壞
- **`ddos probe <host> -p 1-65535`**:async TCP connect scanner,分類 open / closed(RST@SYN)/ filtered(timeout)+ RST-after-data 偵測
- **Config**:YAML + pydantic v2(`src/ddos_tool/config.py`)
- **Metrics**:live pps ticker(stderr)+ end summary(stdout);`--json` 時 stdout 純 JSON(header/ticker 走 stderr)
- **Tests**:43 passed, 2 skipped（未安裝 Scapy/dpkt 時），pytest，**不用 pytest-asyncio**

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
`syn_flood.py` 已具備受控發送、可選 spoofing 與非 spoof 模式 ACK 統計。
- 非 spoof 模式的 `sr()` 等待時間由 `syn.ack_timeout` 控制（預設 0.2s，`0 < x ≤ 5`）；高 RTT 目標可調大，spoof 模式不受影響。
- [x] `syn` optional extra 已加入；未安裝時只在執行 SYN attack 才報錯
- [x] 支援 opt-in **source IP spoofing**（`syn: { spoof_src: "10.0.0.0/8" | random }`）；需 root + `rp_filter=2`
- [x] stats 已區分 `sent` 與 `acked`；非 spoof 模式用 Scapy `sr()` 統計 SYN-ACK，spoof 模式維持 `acked=0`
- **AC**:`ddos run -c cfg.yaml --rps 2000`(attack: syn)對 dev_server 跑 10s,sent ≈ 20k ±15%;`pytest` 全綠(scapy 沒裝時 `test_syn_flood.py` 要 skip,不能 fail)

### R2 (P0)— Auto breaking-point(`--find-limit`) ✅
現在 ramp 是固定 end_rps;要做「跑到壞為止」。
- [x] CLI:`ddos run -c cfg.yaml --ramp-start 500 --ramp-steps 10 --find-limit --err-threshold 5`(%)
- [x] 每 step 結束計算錯誤率；連續 2 個 step ≥ threshold 就停，輸出 `breaking_rps` 到 summary 與 JSON
- [x] `--max-rps` 上限防止 ramp 超過預期
- **AC**:對 dev_server(本地,幾乎不會壞)跑到 max;對真目標應停在 ~5000–6000 rps 附近;JSON 有 `breaking_rps` 欄位

### R3 — 不做
Prometheus endpoint 不在本專案範圍；目前以 stdout / `--json` 作為輸出介面。

### R4 (P1)— pcap replay engine (UDP payload subset)
用真實流量回放,比合成 payload 更貼近。
- [x] optional extra `[replay] = ["dpkt>=1.9"]`;新 attack type `replay`
- [x] config:`replay: { file: "capture.pcap", rate_factor: 2.0 }`(依 timestamp 以 2x 速度回放)
- [x] 僅重播 UDP payload；目的地由 config 重寫，未保留原始 src/link-layer header
- **AC**:對 dev_server 放一個 1s pcap,rate_factor=1 → sent ≈ pcap 內 packet 數 ±10%

### R5 (P1)— UDP engine 效能優化 ✅
已改成 per-worker 長存 transport，payload 只使用 `sendto()`；實際 PPS 需依測試環境驗證。

### R6 (P2)— Payload / source randomization (部分完成)
- [x] `http.body_template`、`http.headers_random`、`udp.fill: random`
- [ ] TCP connect flood 可選 **random src port**(要 raw socket,或接受 OS 分配)
- **AC**:同一 run 內抓 pcap(或用 dev_server 記 payload),確認有變化

### R7 (P2)— `ddos probe` → config 自動串接 ✅
- [x] `ddos probe <host> --emit-config out.yaml` 產生 TCP target YAML，open ports 填入 `tcp.ports`
- **AC**:掃描後產出的 YAML 可直接交給 `ddos run -c` 執行

### R8 — 不做
GitHub Actions CI 不在本專案範圍；測試以本地 `.venv/bin/pytest` 為準。

### R9 — 不做
分散式／遠端 workers 不在本專案範圍；維持單機壓測模擬器定位。

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
.venv/bin/python -m pytest -q                 # 43 passed, 2 skipped（未安裝 optional extras 時）
.venv/bin/python scripts/dev_server.py &      # 本地 target :8099 / :9999
.venv/bin/ddos run -c config/example.yaml --duration 3 --rps 2000
.venv/bin/ddos probe 127.0.0.1 -p 1-100      # scanner
```
