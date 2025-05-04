+++
title = "One Step Further Into ARP: Two Devices Talking Over ARP On My Home Network"
description = "A Guide To Get My Mac and Windows Machines Talking Over ARP" 
date = "2025-05-04"
tags = ['NetworkingBasics', 'ARP', 'MacAndWindows', 'TechExperiment', 'HomeLab']
+++

I have recently taken interest in networking. 
I was exploring how ARP works and came across an informative video from PowerCert YouTube channel.

Link to the video: https://www.youtube.com/watch?v=cn8Zxh9bPio

### Short Summary of ARP 
ARP is used for translating IP addresses to MAC addresses, which is crucial for devices to communicate on a local network.

Before a machine X tries to send some packet to machine Y, machine X needs MAC address of machine Y. So machine X will invoke ARP to get the MAC address of machine Y.

### One Step Further
#### ARP Cache
Every machine has ARP cache. 
When a machine receives an ARP request, it will check its ARP cache to see if it already has the MAC address for the requested IP address. If it does, it will respond with the MAC address. If not, it will send out an ARP request to the network.

So in this blog, I am trying to decipher how does ARP cache between two devices and any scope for communication between both of them.

*Note:* Both the devices are connected to the same network i.e. home wi-fi network.

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

I enjoyed digging into the rabbit hole and experimenting with ARP.

Next time, I’m planning to dig a little deeper, maybe exploring how firewall rules affect ARP or how to sniff these packets directly.

If that sounds interesting, let me know — I’d love to share the next round of findings!

You can reach out to me at [sitasp0](https://twitter.com/sitasp0) on Twitter.
