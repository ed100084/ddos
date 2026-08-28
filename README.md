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
| L7 HTTP flood | asyncio + aiohttp(完整 TLS/HTTP)| 🚧 MVP |
| L4 UDP flood | asyncio datagram / raw socket | ⏳ |
| SYN flood | scapy + raw socket(需 root / `CAP_NET_RAW`)| ⏳ |

## 快速開始

```bash
# 安裝
pip install -e .

# 跑 HTTP flood(MVP)
ddos run --config config/example.yaml
```

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

- **短期(MVP)**:CLI + YAML config + HTTP flood(asyncio/aiohttp)+ UDP flood + token bucket + live pps 顯示。
  - 成功標準:對本地 target 穩定發 50k req/s × 60s,error < 2%。
- **中期**:SYN flood(scapy)、payload template、Prometheus/Grafana dashboard、pcap replay(真實流量回放)。
- **長期**:分散式 workers(Redis queue,botnet-like)、多機協調、自動報告。

## Repo 結構

```
ddos/
├── pyproject.toml
├── config/example.yaml
├── src/ddos_tool/
│   ├── cli.py            # click entry: ddos run --config ...
│   ├── config.py         # YAML + pydantic validation
│   ├── engine/base.py    # worker ABC + token bucket
│   ├── engine/http_flood.py
│   ├── engine/udp_flood.py
│   ├── engine/syn_flood.py
│   ├── metrics.py        # counters / Prometheus
│   └── reporter.py       # 結束 summary
└── tests/
```

## 風險

1. **特權**:raw socket 要 root 或 `CAP_NET_RAW`;IP spoofing 還要關 `rp_filter` — 生產機上跑要小心。
2. **法律 / 倫理**:打非自己的 target(醫療環境的鄰居可能是病歷系統)→ noisy neighbor + 法務問題。
3. **Backpressure**:目標 drop packet 時 sender 會變成瓶頸,metrics 要同時記 sent / acked / dropped。

## License

TBD(MIT?)
