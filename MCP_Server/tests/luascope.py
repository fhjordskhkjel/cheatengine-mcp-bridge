"""Tiny Lua 5.3 tokenizer + block tracker: chunk-level locals and their uses."""
import re

KEYWORDS = {"and","break","do","else","elseif","end","false","for","function","goto","if","in",
            "local","nil","not","or","repeat","return","then","true","until","while"}

def tokenize(src):
    """Yield (kind, value, line, pos). kinds: name, kw, str, num, op."""
    i, n, line = 0, len(src), 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1; i += 1; continue
        if c in " \t\r":
            i += 1; continue
        if src.startswith("--", i):
            m = re.match(r"--\[(=*)\[", src[i:])
            if m:
                close = "]" + m.group(1) + "]"
                j = src.index(close, i) + len(close)
            else:
                j = src.find("\n", i)
                j = n if j < 0 else j
            line += src.count("\n", i, j); i = j; continue
        m = re.match(r"\[(=*)\[", src[i:])
        if m:
            close = "]" + m.group(1) + "]"
            j = src.index(close, i) + len(close)
            yield ("str", src[i:j], line, i); line += src.count("\n", i, j); i = j; continue
        if c in "\"'":
            j = i + 1
            while src[j] != c:
                j += 2 if src[j] == "\\" else 1
            yield ("str", src[i:j+1], line, i); line += src.count("\n", i, j); i = j + 1; continue
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", src[i:])
        if m:
            w = m.group(0)
            yield ("kw" if w in KEYWORDS else "name", w, line, i); i += len(w); continue
        m = re.match(r"0[xX][0-9a-fA-F]+|\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+", src[i:])
        if m:
            yield ("num", m.group(0), line, i); i += len(m.group(0)); continue
        m = re.match(r"\.\.\.|\.\.|==|~=|<=|>=|<<|>>|//|::|.", src[i:], re.S)
        yield ("op", m.group(0), line, i); i += len(m.group(0))

def analyze(src):
    """Return (chunk_locals, refs, assigns).
    chunk_locals: list of (name, line) declared at block depth 0.
    refs: list of (name, line) of every identifier used as a variable (not a field/key).
    assigns: list of (name, line, depth) for `name =` statements that are not `local`.
    """
    toks = list(tokenize(src))
    depth, pending_do = 0, 0
    brace = 0
    chunk_locals, refs, assigns = [], [], []
    for k, (kind, val, line, pos) in enumerate(toks):
        prev = toks[k-1] if k else None
        nxt = toks[k+1] if k + 1 < len(toks) else None
        if kind == "kw":
            if val in ("function", "repeat", "if"):
                depth += 1
            elif val in ("while", "for"):
                depth += 1; pending_do += 1
            elif val == "do":
                if pending_do: pending_do -= 1
                else: depth += 1
            elif val in ("end", "until"):
                depth -= 1
            elif val == "local" and depth == 0:
                j = k + 1
                if toks[j][1] == "function":
                    chunk_locals.append((toks[j+1][1], line))
                else:
                    while True:
                        chunk_locals.append((toks[j][1], line))
                        if toks[j+1][1] == ",": j += 2
                        else: break
            continue
        if kind == "op":
            if val == "{": brace += 1
            elif val == "}": brace -= 1
            continue
        if kind != "name":
            continue
        if prev and prev[1] in (".", ":", "goto", "::"):
            continue                      # field access / method / label
        if prev and prev[1] == "function" and nxt and nxt[1] in (".", ":"):
            pass                          # function a.b() -> 'a' is a reference
        if nxt and nxt[1] == "=" and brace > 0 and prev and prev[1] in ("{", ","):
            continue                      # table constructor key: { name = ... }
        refs.append((val, line))
        if nxt and nxt[1] == "=" and brace == 0 and not (prev and prev[1] == "local"):
            # statement-level assignment (also covers `a, b = ...` first name only)
            assigns.append((val, line, depth))
    return chunk_locals, refs, assigns
