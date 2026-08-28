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
    → Attack modules (http / udp / syn) → Rate limiter (token bucket)
    → Metrics (counters, Prometheus) → Reporter (summary)
```

## 攻擊引擎

| 模組 | 方案 | 狀態 |
|---|---|---|
| L7 HTTP flood | asyncio + aiohttp(完整 TLS/HTTP)| ✅ |
| L4 UDP flood | asyncio datagram endpoint | ✅ |
| L4 TCP connect flood | asyncio open/close,可多 port round-robin | ✅ |
| SYN flood | scapy raw socket(需 root / `CAP_NET_RAW`)| 🚧 選裝(`pip install scapy`) |

## 快速開始

```bash
# 安裝
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

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
| `-c, --config` | YAML config(必填)|
| `-d, --duration` | 覆蓋 `duration_sec` |
| `--rps` | 覆蓋 `rate.rps`(ramp 時忽略)|
| `--ramp-start / --ramp-end` | **升速**:起始 → 結束 rps |
| `--ramp-steps` | 升速級數(預設 5),每級顯示 ops + err% |
| `-q, --quiet` | 關掉 live pps 顯示 |

```bash
# 升速找 breaking point:500 → 6000 rps,6 級
ddos run -c config/target-222.yaml --ramp-start 500 --ramp-end 6000 --ramp-steps 6
```

> **實測(222.179.105.17)**:瓶頸是**同時連線數**,不是頻寬 — 3000 rps @ 64 workers = 0% err,同 rate @ 300 workers = 85% err。

### `ddos probe` — port scanner(打之前先掃)

```bash
# 全 port TCP connect scan + RST-after-data 偵測
ddos probe 222.179.105.17 -p 1-65535 -c 2000 -t 1.0

# 指定 port / range
ddos probe 10.0.0.5 -p 80,443,8000-9000
```

輸出分類:`open`(✓ holds connection = 真 service / ⚠ RST-after-data = firewall/middlebox)、`closed`(RST@SYN)、`filtered`(timeout)。

### 驗證過的 smoke test(單機)

- HTTP:2000 rps × 5s → **10,500 req,100% ok**
- UDP:5000 rps × 3s → **~16k packets,100% ok**(server 端同步收到)

### Example config

```yaml
target: https://example.com/
attack: http
duration_sec: 60
rate:            # token bucket
  rps: 50000     # requests per second
workers: 16      # asyncio workers
payload:
  path: /
  method: GET
  headers:
    User-Agent: ddos-tool/0.1
```

## Roadmap

- ✅ **短期(MVP)**:CLI + YAML config + HTTP flood(asyncio/aiohttp)+ UDP flood + token bucket + live pps 顯示 + dev target server + tests。
- **中期**:SYN flood 除錯(scapy)、payload template、Prometheus/Grafana dashboard、pcap replay(真實流量回放)。
- **長期**:分散式 workers(Redis queue,botnet-like)、多機協調、自動報告。

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
│   ├── engine/syn_flood.py
│   ├── metrics.py        # live pps + summary
│   ├── probe.py          # TCP connect scanner (ddos probe)
│   └── reporter.py       # 結束 summary
└── tests/                # config / token bucket / HTTP e2e / probe
```

## 風險

1. **特權**:raw socket 要 root 或 `CAP_NET_RAW`;IP spoofing 還要關 `rp_filter` — 生產機上跑要小心。
2. **法律 / 倫理**:打非自己的 target(醫療環境的鄰居可能是病歷系統)→ noisy neighbor + 法務問題。
3. **Backpressure**:目標 drop packet 時 sender 會變成瓶頸,metrics 要同時記 sent / acked / dropped。

## License

TBD(MIT?)
