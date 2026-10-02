# NetPhish Formal Detection Heuristics & Scoring Catalog

**Author:** Hrudyansh Kayastha  
**Version:** 2.0.0  
**Classification:** Detection Engineering Specification  

---

## 1. Static URL Phishing Rules

The static URL analyzer extracts 15 lexical and structural signals completely offline without generating network traffic or socket calls.

| Rule ID | Detection Name | Condition / Heuristic | Severity | Score Weight |
|---|---|---|---|---|
| `RULE-URL-IPHOST` | Direct IP-Based Hostname | Hostname matches valid decimal IPv4 format (`a.b.c.d`) | **HIGH** | +20.0 pts |
| `RULE-URL-NOHTTPS` | Unencrypted HTTP Scheme | URI scheme is plaintext `http://` instead of `https://` | **MEDIUM** | +15.0 pts |
| `RULE-URL-PUNYCODE` | Punycode (IDN) Hostname | Hostname contains internationalized `xn--` prefix | **HIGH** | +15.0 pts |
| `RULE-URL-KEYWORD` | Suspicious Keyword Lure | Subdomain, path, or query contains authentication/financial lure (`login`, `verify`, `account`, `password`, `bank`, `update`) | **MEDIUM** | +10.0 pts |
| `RULE-URL-SHORTENER` | URL Shortener Redirection | Hostname matches known public redirection service (`bit.ly`, `tinyurl.com`, `t.co`, `ow.ly`, etc.) | **MEDIUM** | +10.0 pts |
| `RULE-URL-EXCSUB` | Excessive Subdomain Depth | Subdomain contains $\ge 3$ labels or hostname depth $\ge 4$ | **MEDIUM** | +10.0 pts |
| `RULE-URL-SUSPTLD` | High-Risk TLD | Top-level domain matches disposable or abuse-prone extensions (`.xyz`, `.top`, `.loan`, `.work`, `.click`, `.tk`) | **MEDIUM** | +10.0 pts |
| `RULE-URL-ATSYM` | @ Symbol Obfuscation | URI contains `@` symbol or username authority delimiter hiding true destination host | **HIGH** | +10.0 pts |
| `RULE-URL-SEP` | Repeated Separator Pattern | URI contains repeated slashes (`//`), multiple hyphens (`--`), or directory traversal (`..`) | **MEDIUM** | +10.0 pts |
| `RULE-URL-CHARDENS` | High Special Character Density | Punctuation character ratio exceeds 15% of total length or special character count > 10 | **LOW** | +10.0 pts |
| `RULE-URL-ENCODING` | Obfuscated Percent-Encoding | URI contains $\ge 3$ percent-encoded sequences or path obfuscations (`%2e`, `%2f`) | **LOW** | +5.0 pts |
| `RULE-URL-BRAND` | Brand Name Mismatch | Trusted brand keyword (e.g. `paypal`, `microsoft`, `google`, `apple`) present in path/query while registered domain is unrelated | **MEDIUM** | +10.0 pts |

*URL Subtotal Cap:* 100.0 raw points, normalized to 40.0 maximum points in composite risk evaluation.

---

## 2. Behavioral Network Threat Rules

The Scapy network analyzer parses offline `.pcap` captures, aggregates bidirectional 5-tuple flows `(src_ip, dst_ip, src_port, dst_port, protocol)`, and evaluates behavioral sliding-window heuristics.

### 2.1 Possible Port Scan (`RULE-NET-SCAN`)
- **Condition:** A single source IP probes $\ge 10$ unique destination ports on a target IP within a sliding 60-second window.
- **Evidence:** Target host, count of probed ports, sample port numbers.
- **Severity:** **HIGH** (+20.0 pts)

### 2.2 High Connection Rate (`RULE-NET-RATE`)
- **Condition:** A source host initiates $\ge 50$ packets or connections within a sliding 10-second window.
- **Evidence:** Packet burst volume, window duration.
- **Severity:** **MEDIUM** (+15.0 pts)

### 2.3 Periodic C2 Beaconing (`RULE-NET-BEACON`)
- **Condition:** Regular connection intervals between a host pair with low variance:
  1. Minimum connections: $N \ge 4$.
  2. Inter-arrival intervals: $\Delta t_i = t_{i} - t_{i-1}$ where $\Delta t_i > 0.05\text{s}$.
  3. Mean interval: $\mu = \frac{1}{k} \sum_{i=1}^k \Delta t_i \ge 0.5\text{s}$.
  4. Standard deviation: $\sigma = \sqrt{\frac{1}{k} \sum_{i=1}^k (\Delta t_i - \mu)^2}$.
  5. Coefficient of Variation: $CV = \frac{\sigma}{\mu} \le 0.35$.
- **Evidence:** Total contacts, average interval $\mu$, variance coefficient $CV$.
- **Severity:** **HIGH** (+20.0 pts)

### 2.4 ICMP Burst / Flood Sweep (`RULE-NET-ICMP`)
- **Condition:** $\ge 20$ ICMP packets observed within a sliding 10-second window.
- **Evidence:** ICMP packet count, source IP, destination IP.
- **Severity:** **MEDIUM** (+10.0 pts)

### 2.5 Unusual Destination Port (`RULE-NET-UNUSUALPORT`)
- **Condition:** TCP or UDP traffic targeting ports outside the common service registry (ports outside standard list of 20 service ports such as 80, 443, 53, 22, etc.).
- **Evidence:** Non-standard port numbers observed in session flows.
- **Severity:** **LOW** (+10.0 pts)

### 2.6 Repeated Outbound Connections (`RULE-NET-REPEAT`)
- **Condition:** $\ge 10$ packets exchanged between a host pair across multiple sessions (when port scan is not triggered).
- **Evidence:** Packet exchange volume between specific host pair.
- **Severity:** **LOW** (+15.0 pts)

### 2.7 DNS Query Anomaly (`RULE-NET-DNS`)
- **Condition:** Fully qualified domain query length exceeds 50 characters OR subdomain chain depth $\ge 4$ labels.
- **Evidence:** Query string, character length, label count.
- **Severity:** **MEDIUM** (+10.0 pts)

### 2.8 Suspicious HTTP Metadata (`RULE-NET-HTTP`)
- **Condition:**
  - HTTP request issued directly to an IPv4 host header (`Host: 203.0.113.50`).
  - Cleartext credential parameters exposed in URI query (`password=`, `token=`, `auth=`).
- **Evidence:** Host header value, URI snippet.
- **Severity:** **MEDIUM** to **HIGH** (+10.0 pts)

---

## 3. Multi-Source Evidence Correlation

| Correlation Type | Condition | Severity / Weight |
|---|---|---|
| `CROSS_SOURCE_IPv4_MATCH` | Target URL host IP matches PCAP flow destination IP | **CRITICAL** (+15.0 pts) |
| `CROSS_SOURCE_DOMAIN_MATCH` | Target URL hostname matches PCAP DNS query or HTTP Host header | **HIGH** (+15.0 pts) |
| `TEMPORAL_COINCIDENCE` | Correlated indicators occur within $|\Delta t| \le 300\text{ seconds}$ ($\pm 5$ minutes) | **HIGH** (+15.0 pts) |

---

## 4. Unified Risk Engine

$$\text{Total Score} = \min\left(100.0, \; \text{URL}(40) + \text{PCAP}(40) + \text{IOC Match}(15) + \text{Temporal Proximity}(15)\right)$$

### Posture Thresholds
- `0.0 - 29.9`: **LOW**
- `30.0 - 59.9`: **MEDIUM**
- `60.0 - 79.9`: **HIGH**
- `80.0 - 100.0`: **CRITICAL**
