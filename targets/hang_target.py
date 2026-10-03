"""A tokenizer that loops forever on a trailing backslash (hang detection demo)."""


def tokenize(data: bytes):
    i, out = 0, []
    while i < len(data):
        c = data[i]
        if c == 0x20:
            i += 1
        elif 0x30 <= c <= 0x39:
            j = i
            while j < len(data) and 0x30 <= data[j] <= 0x39:
                j += 1
            out.append(int(data[i:j]))
            i = j
        elif c == 0x5C and i + 1 >= len(data):
            continue                      # BUG: never advances -> infinite loop
        else:
            out.append(c)
            i += 1
    return out
