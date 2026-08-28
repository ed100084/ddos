# ddos-tool

Python 開發的 DDoS **模擬器 / Flood Generator** — 用來壓測自家入口(WAF、CDN、防火牆)扛不扛得住,不是偵測系統。

## 定位

| 類型 | 目的 | 本專案 |
|---|---|---|
| **A. Flood Generator**(攻擊模擬)| 驗證 WAF/CDN/防火牆的承載能力 | ✅ 就是這個 |
| B. Detection / Mitigation | 從流量中辨識 DDoS 並擋掉 | ❌ |
| C. 真實攻擊武器 | 打別人的 target(法務風險高)| ❌ |

> **誠實定位**:Python 單機大約 10–50k pps(L4)/ 數萬 req/s(L7),離真實 Tbps DDoS 差很遠 — 它是「模擬器」,不是武器。

## 架構

```
CLI (click) → Config (YAML + pydantic) → Engine (asyncio workers)
    → Attack modules (http / udp / tcp / tls / syn / replay) → Rate limiter (token bucket)
    → Metrics (counters) → Reporter (summary / JSON)
```

## 攻擊引擎

| 模組 | 方案 | 狀態 |
|---|---|---|
| L7 HTTP flood | asyncio + aiohttp(完整 TLS/HTTP)| ✅ |
| L4 UDP flood | asyncio datagram endpoint | ✅ |
| L4 TCP connect flood | asyncio open/close,可多 port round-robin | ✅ |
| TLS handshake flood | asyncio TLS connect/close | ✅ |
| SYN flood | scapy raw socket(需 root / `CAP_NET_RAW`)| 🚧 選裝(`pip install -e '.[syn]'`) |
| UDP pcap replay | dpkt payload replay with timestamp scaling | ✅ 選裝(`pip install -e '.[replay]'`) |

## 快速開始

```bash
# 安裝
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
# Optional raw SYN engine (requires root/CAP_NET_RAW at runtime):
# pip install -e ".[dev,syn]"

# 起本地 target(驗證用)
python scripts/dev_server.py --port 8099 --udp-port 9999 &

# 跑 HTTP flood
ddos run -c config/example.yaml --duration 5 --rps 2000

# 跑 UDP flood
ddos run -c /tmp/udp.yaml          # attack: udp, target: host:port
```

### CLI options

| Flag | 作用 |
|---|---|
| `-c, --config` | YAML config（可選；不用時搭配 `--target` 或 `--host`/`--port`，以及 `--attack`）|
| `--target` / `--host` / `--port` / `--attack` | 不使用 YAML 時直接指定 target；TCP/UDP/TLS/SYN/replay 可拆成 host + port |
| `-d, --duration` | 覆蓋 `duration_sec` |
| `--rps` | 覆蓋 `rate.rps`(ramp 時忽略)|
| `--workers` / `--udp-size` / `--udp-fill` | 覆蓋 worker 與 UDP payload 設定 |
| `--tcp-ports` | 覆蓋 TCP port 清單，例如 `80,8080` |
| `--http-method` / `--http-path` / `--http-body` | 覆蓋 HTTP request 設定 |
| `--syn-spoof-src` | SYN source spoofing（`random` 或 IPv4 CIDR） |
| `--ramp-start / --ramp-end` | **升速**:起始 → 結束 rps |
| `--ramp-steps` | 升速級數(預設 5),每級顯示 ops + err% |
| `--find-limit` / `--err-threshold` / `--max-rps` | 連續兩階段錯誤超標時自動停止並回報 breaking RPS |
| `--max-packets` | replay 封包數上限 |
| `--json` | stdout 輸出機器可讀 JSON(header/ticker 走 stderr)|
| `-q, --quiet` | 關掉 live pps 顯示 |

> 📋 **要繼續開發?** 看 [`REQUIREMENTS.md`](REQUIREMENTS.md)— 自足的需求 backlog(P0–P2)+ 架構慣例 + 目標機實測事實,給接手的人/AI 用。

不想建立 local YAML 時，可直接用 CLI（`--config` 現在是可選的）：

```bash
ddos run --host 10.0.0.5 --port 9999 --attack udp --duration 30 \
  --rps 20000 --workers 16 --udp-size 512 --udp-fill x
```

TLS handshake 測試（`host:port`，完成握手後立即關閉）：

```bash
ddos run --host 127.0.0.1 --port 8443 --attack tls --rps 100 --duration 10
```

安全版 pcap replay 只重播 UDP payload，並重寫目的地；會依 pcap timestamp 重現封包間隔，
`rate_factor: 2.0` 代表時間間隔縮短為一半（需 `pip install -e '.[replay]'`）：

```yaml
target: 127.0.0.1:9999
attack: replay
replay: {file: capture.pcap, rate_factor: 2.0}
```

```bash
# 升速找 breaking point:500 → 6000 rps,6 級
ddos run -c config/example-target.yaml --ramp-start 500 --ramp-end 6000 --ramp-steps 6
```

自動尋找容量上限：

```bash
ddos run -c config/example-target.yaml --ramp-start 500 \
  --find-limit --err-threshold 5 --max-rps 10000 --ramp-steps 10
```

> **實測(203.0.113.17)**:瓶頸是**同時連線數**,不是頻寬 — 3000 rps @ 64 workers = 0% err,同 rate @ 300 workers = 85% err。

### `ddos probe` — port scanner(打之前先掃)

```bash
# 全 port TCP connect scan + RST-after-data 偵測
ddos probe 203.0.113.17 -p 1-65535 -c 2000 -t 1.0

# 指定 port / range
ddos probe 10.0.0.5 -p 80,443,8000-9000

# 掃描結果產生 TCP run config
ddos probe 10.0.0.5 -p 80,443 --emit-config /tmp/target.yaml
```

輸出分類:`open`(✓ holds connection = 真 service / ⚠ RST-after-data = firewall/middlebox)、`closed`(RST@SYN)、`filtered`(timeout)。

### 驗證過的 smoke test(單機)

- HTTP:2000 rps × 5s → **10,500 req,100% ok**
- UDP:5000 rps × 3s → **~16k packets,100% ok**（歷史基準；實際 PPS 依環境而異）

### Example config

```yaml
target: https://example.com/
attack: http
duration_sec: 60
rate:            # token bucket
  rps: 50000     # requests per second
workers: 16      # asyncio workers
http:
  path: /
  method: GET
  headers:
    User-Agent: ddos-tool/0.1
```

HTTP 可用 `body_template: "id={rand_int}"` 產生每 request 不同內容，並以
`headers_random: {X-Test: [a, b]}` 隨機選 header 值；UDP 設定 `fill: random` 可產生每包不同 payload。

SYN 非 spoof 模式可在 YAML 以 `syn: {ack_timeout: 0.2}` 調整 ACK 等待時間（0–5 秒）。

## Roadmap

- ✅ **已完成**：HTTP、UDP、TCP connect、TLS handshake、probe、ramp、JSON 報告、payload randomization、UDP pcap replay、probe config export。
- 🚧 **進階/部分完成**：SYN（需 Scapy/root；spoof 與 ACK tracking）；pcap replay 目前只支援 UDP payload；TCP random source port 未提供專用旗標。
- 📌 **下一步**：補充 replay parser/timing 測試與單機 smoke benchmarks。
- ⛔ **明確不做**：Prometheus/Grafana、GitHub Actions CI、分散式 workers。

## Repo 結構

```
ddos/
├── pyproject.toml
├── config/example.yaml
├── scripts/dev_server.py # 本地 target(HTTP counter + UDP sink)
├── src/ddos_tool/
│   ├── cli.py            # click entry: ddos run --config ...
│   ├── config.py         # YAML + pydantic validation
│   ├── engine/base.py    # AttackEngine ABC + TokenBucket
│   ├── engine/http_flood.py
│   ├── engine/udp_flood.py
│   ├── engine/tcp_flood.py
│   ├── engine/tls_flood.py
│   ├── engine/replay.py
│   ├── engine/syn_flood.py
│   ├── metrics.py        # live pps + summary
│   ├── probe.py          # TCP connect scanner (ddos probe)
│   └── reporter.py       # 結束 summary
└── tests/                # config / engines / CLI / probe / reporter
```

## 風險

1. **特權**:raw socket 要 root 或 `CAP_NET_RAW`;IP spoofing 還要關 `rp_filter` — 生產機上跑要小心。
2. **法律 / 倫理**:打非自己的 target(醫療環境的鄰居可能是病歷系統)→ noisy neighbor + 法務問題。
3. **Backpressure**:目標 drop packet 時 sender 會變成瓶頸,metrics 要同時記 sent / acked / dropped。

## License

TBD(MIT?)
