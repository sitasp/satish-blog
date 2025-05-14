+++
title = "Pushing My Local Server to the Limit: Building a Load Testing CLI with `wrknoob`"
description = "Load testing seemed strange to me, so I built a CLI to make it easier."
date = "2025-05-14"
tags = ['LoadTesting', 'load-testing']
+++

Lately, I’ve been tuning a Quarkus backend and got curious: *How many concurrent requests can this thing actually handle?* That’s when I stumbled upon [`wrk`](https://github.com/wg/wrk), a modern HTTP benchmarking tool that’s fast and flexible — but also a little unfriendly if you're just starting out.

So I built a wrapper: **`wrknoob`** — a simple, noob-friendly Python CLI that wraps around `wrk`, runs structured load tests, and shows beautiful terminal tables and plots. Here’s how it went.

---

### The Problem

I could run commands like:

```bash
wrk -t8 -c100 -d15s http://localhost:8080/hello
```

But over time, I wanted:

- To **test across multiple concurrency levels**
- To **automatically visualize** requests/sec and latency
- To **save results to CSV**
- To avoid flipping between notes and terminal

I didn’t want a full-fledged Grafana dashboard or a k6 setup — just something **quick, scriptable, and pretty.**

---

## Enter `wrknoob`

I created a Python CLI tool that:

✅ Asks for input parameters interactively  
✅ Runs `wrk` for each concurrency level  
✅ Parses and displays the output beautifully with [rich](https://github.com/Textualize/rich)  
✅ Plots graphs using `matplotlib`  
✅ Can save results to CSV and images

---

### Features in a Nutshell

- 🎛️ Prompt-based test configuration
- 📊 Graph of requests/sec across concurrencies
- 📉 Latency trend analysis
- 🧾 Rich terminal table for results
- 💾 Export to `report.csv` and `plot.png`

---

### Screenshot

![wrknoob demo screenshot](/images/wrknoob-screenshot.png)

> Above: Results table in terminal and corresponding plot

---

### Installation

You’ll need Python 3.8+ and `wrk` installed. On macOS:

```bash
brew install wrk
```

Then:

```bash
git clone https://github.com/sitasp/wrknoob.git
cd wrknoob
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run with:

```bash
python wrknoob.py
```

---

### Sample Run

```bash
Target URL: http://localhost:8080/hello
Test Duration (e.g., 10s): 10
Threads: 4
Concurrent Connections (comma-separated): 10,25,50,100
Show Graph? [y/n]: y
Save Report to CSV? [y/n]: y
```

Output:

- `report.csv` — with columns like concurrency, req/sec, latency
- `plot.png` — a visual trend of performance

---

### Why I Built This

Load testing felt like a mysterious black box — but writing `wrknoob` helped me understand:

- The relationship between **latency and concurrency**
- How **saturation** begins to degrade performance
- That **high req/sec != efficient** if latency spikes

---

### Final Thoughts

If you're testing your APIs, especially on localhost, `wrknoob` helps you **benchmark easier** without sweating over `wrk` flags. It’s not meant for enterprise-scale simulation, but it’s perfect for developers experimenting with performance.

Check out the repo [here](https://github.com/sitasp/wrknoob), and feel free to open issues or PRs!

Happy benchmarking!
