+++
title = "Hello, World!"
description = "hello"
date = 2025-12-01

[extra]
lang = "en"
toc = false
comment = false
math = true
+++

Obligatory first post. Here's Euler's identity:

$$e^{i\pi} + 1 = 0$$

And here's some weird looking Python code that does... something:

```python
# py3.14
exec(type((lambda: ...).__code__)(
    *(0x00,)*0x04, 0x03, 0x00,
    bytes([0x80, 0x00, 0x5d, 0x00, 0x21, 0x00, 0x52, 0x00,
           0x34, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x1f, 0x00, 0x52, 0x01, 0x23, 0x00]),
    (bytes(c^0x2a for c in b'YOMLK_F^').decode(), None),
    (bytes(c^0x2a for c in b'ZXCD^').decode(),),
    (), *['']*0x03, 0x01, *[b'']*0x02, *[()]*0x02
))
```

```c
PyDoc_STRVAR(code_new__doc__,
"code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n"
"     flags, codestring, constants, names, varnames, filename, name,\n"
"     qualname, firstlineno, linetable, exceptiontable, freevars=(),\n"
"     cellvars=(), /)\n"
"--\n"
"\n"
"Create a code object.  Not for the faint of heart.");
```
