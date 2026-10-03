"""A binary packet parser with two planted bugs hidden behind a 4-byte magic.

Layout: MAGIC(4)='FUZZ' | version(1) | flags(1) | length(1) | payload...

Each magic byte is checked in its own nested ``if`` so a blind fuzzer needs
~256^4 attempts, while a coverage-guided one climbs the checks one byte at a
time (every new matching byte reveals a new line = new coverage).
"""


def parse_packet(data: bytes):
    if len(data) < 8:
        return None
    if data[0] == 0x46:                      # 'F'
        if data[1] == 0x55:                  # 'U'
            if data[2] == 0x5A:              # 'Z'
                if data[3] == 0x5A:          # 'Z'
                    version, flags, length = data[4], data[5], data[6]
                    if version == 2:
                        # BUG A: ratio of two header bytes, divisor never checked
                        return data[7] // (data[8] if len(data) > 8 else 0) if flags & 1 else 0
                    if version == 1 and flags & 0x80:
                        # BUG B: trailer byte read without a bounds check
                        if length > 0 and length < 32:
                            payload = data[7:7 + length]
                            checksum = sum(payload) & 0xFF
                            return checksum ^ data[7 + length]
                    return len(data)
    return None
