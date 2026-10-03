"""A small recursive-descent JSON parser with two planted bugs.

Malformed JSON is *expected* and raises ParseError (swallowed by the harness).
Anything else that escapes is a real bug the fuzzer should find:
  * a lone '-' reaches int('-') and raises ValueError
  * a \\u escape with non-hex digits raises ValueError instead of ParseError
"""


class ParseError(Exception):
    pass


class _Parser:
    def __init__(self, s: str):
        self.s, self.i = s, 0

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] in " \t\r\n":
            self.i += 1

    def value(self, depth=0):
        if depth > 50:
            raise ParseError("too deep")
        self.ws()
        if self.i >= len(self.s):
            raise ParseError("eof")
        c = self.s[self.i]
        if c == "{":
            return self.obj(depth)
        if c == "[":
            return self.arr(depth)
        if c == '"':
            return self.string()
        if c == "-" or c.isdigit():
            return self.number()
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.s.startswith(word, self.i):
                self.i += len(word)
                return val
        raise ParseError("unexpected " + c)

    def obj(self, depth):
        self.i += 1
        out = {}
        self.ws()
        if self.s[self.i:self.i + 1] == "}":
            self.i += 1
            return out
        while True:
            self.ws()
            key = self.string()
            self.ws()
            if self.s[self.i:self.i + 1] != ":":
                raise ParseError("expected :")
            self.i += 1
            out[key] = self.value(depth + 1)
            self.ws()
            ch = self.s[self.i:self.i + 1]
            self.i += 1
            if ch == "}":
                return out
            if ch != ",":
                raise ParseError("expected , or }")

    def arr(self, depth):
        self.i += 1
        out = []
        self.ws()
        if self.s[self.i:self.i + 1] == "]":
            self.i += 1
            return out
        while True:
            out.append(self.value(depth + 1))
            self.ws()
            ch = self.s[self.i:self.i + 1]
            self.i += 1
            if ch == "]":
                return out
            if ch != ",":
                raise ParseError("expected , or ]")

    def string(self):
        if self.s[self.i:self.i + 1] != '"':
            raise ParseError("expected string")
        self.i += 1
        buf = []
        while self.i < len(self.s):
            c = self.s[self.i]
            self.i += 1
            if c == '"':
                return "".join(buf)
            if c == "\\":
                e = self.s[self.i:self.i + 1]
                self.i += 1
                if e == "u":
                    buf.append(chr(int(self.s[self.i:self.i + 4], 16)))  # BUG: no hex validation
                    self.i += 4
                elif e in '"\\/':
                    buf.append(e)
                elif e == "n":
                    buf.append("\n")
                elif e == "t":
                    buf.append("\t")
                else:
                    raise ParseError("bad escape")
            else:
                buf.append(c)
        raise ParseError("unterminated string")

    def number(self):
        start = self.i
        if self.s[self.i] == "-":
            self.i += 1
        while self.i < len(self.s) and self.s[self.i].isdigit():
            self.i += 1
        return int(self.s[start:self.i])  # BUG: '-' alone -> ValueError


def fuzz_json(data: bytes):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        return _Parser(text).value()
    except ParseError:
        return None
