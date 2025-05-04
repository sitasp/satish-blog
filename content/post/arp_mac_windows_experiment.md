+++
title = "Exploring ARP: Connecting My MacBook and Windows PC"
date = "2025-05-04"
tags = ['NetworkingBasics', 'ARP', 'MacAndWindows', 'TechExperiment', 'HomeLab']
+++

Sometimes I get curious about the basics — like, really basic.

Even though I work with higher-level tools every day, I wanted to step back and understand how two of my own machines talk to each other on the network, right down at the ARP level. This post is a walk-through of that little experiment: no fancy tools, no external scripts — just the commands you can run on macOS and Windows to watch devices discover each other.

---

## Objective

I have two partner devices:
- **Device 1**: MacBook Pro
- **Device 2**: Windows machine

My goal: get each device’s MAC and IP address into the ARP cache of the other.

---

### Step 1: Check IP Address on Windows

**Command (Windows CMD):**
```
ipconfig
```

**Output:**
```
Wireless LAN adapter WiFi:

   IPv4 Address. . . . . . . . . . . : 192.168.31.190
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.31.1
```

---

### Step 2: Clear ARP Cache on Windows

**Command:**
```
netsh interface ip delete arpcache
```

**Output:**
```
Ok.
```

---

### Step 3: Check IP Address on macOS

**Command (macOS Terminal):**
```
ifconfig | grep inet
```

**Output:**
```
inet 192.168.31.216 netmask 0xffffff00 broadcast 192.168.31.255
```

---

### Step 4: Clear ARP Cache on macOS

**Command:**
```
sudo arp -a -d
```

**Output (sample):**
```
192.168.31.1 (192.168.31.1) deleted
192.168.31.190 (192.168.31.190) deleted
192.168.31.255 (192.168.31.255) deleted
```

*Note:* I masked the MAC addresses here for privacy.

---

### Step 5: Ping Windows from MacBook

**Command (macOS Terminal):**
```
ping 192.168.31.190
```

**Output:**
```
PING 192.168.31.190 (192.168.31.190): 56 data bytes
Request timeout for icmp_seq 0
Request timeout for icmp_seq 1
Request timeout for icmp_seq 2
...
```

Meanwhile, checking the Windows ARP cache:

**Command (Windows CMD):**
```
arp -a
```

**Output:**
```
Interface: 192.168.31.190 --- 0x2
  Internet Address      Physical Address      Type
  192.168.31.1          98-87-4c-37-25-1d     dynamic
  (No entry yet for MacBook)
```

---

### Step 6: Traceroute from MacBook to Windows

**Command (macOS Terminal):**
```
traceroute 192.168.31.190
```

**Output (trimmed):**
```
traceroute to 192.168.31.190 (192.168.31.190), 64 hops max
 1  * * *
 2  * * *
 3  * * *
...
16  * * *
```

After this, I checked the Windows ARP cache again and finally found the MacBook’s entry.

---

### Step 7: Verify ARP Cache on Both Machines

**Windows (CMD):**
```
arp -a
```

**Sample Output:**
```
Interface: 192.168.31.190 --- 0x2
  192.168.31.216        XX-XX-XX-XX-XX-b0     dynamic (MacBook)
```

**macOS (Terminal):**
```
arp -a
```

**Sample Output:**
```
? (192.168.31.190) at XX:XX:XX:XX:XX:a9 on en0 ifscope [ethernet] (Windows)
```

*Note:* MAC addresses are masked for privacy.

---

## Final Thoughts

I find these small network experiments satisfying because they remind me how much is happening under the hood every time we casually load a webpage or sync a file. If you try something similar on your own machines, you might notice differences depending on your network, firewall, or even your OS version — and that’s part of the fun.

Next time, I’m planning to dig a little deeper, maybe exploring how firewall rules affect ARP or how to sniff these packets directly.

If that sounds interesting, let me know — I’d love to share the next round of findings!

You can reach out to me at [sitasp](https://twitter.com/sitasp) on Twitter.
