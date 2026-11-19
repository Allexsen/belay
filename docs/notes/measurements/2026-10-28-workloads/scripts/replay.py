"""Replay a wlog over an initial file. Yields (t0, t1, state bytes) per record; final check."""
import struct, sys
REC = struct.Struct('<QQqqii')
def records(log):
    with open(log, 'rb') as f:
        while True:
            h = f.read(REC.size)
            if len(h) < REC.size: return
            t0, t1, off, ln, kind, _ = REC.unpack(h)
            data = f.read(ln) if kind == 1 else b''
            yield t0, t1, off, ln, kind, data
def apply(buf, off, ln, kind, data):
    if kind == 2:
        if off < len(buf): del buf[off:]
        else: buf.extend(b'\0' * (off - len(buf)))
    else:
        if off > len(buf): buf.extend(b'\0' * (off - len(buf)))
        buf[off:off + len(data)] = data
if __name__ == '__main__':
    init, log, final = sys.argv[1:4]
    buf = bytearray(open(init, 'rb').read()); n = 0
    for t0, t1, off, ln, kind, data in records(log):
        apply(buf, off, ln, kind, data); n += 1
    print(n, 'writes replayed; equals final file:', bytes(buf) == open(final, 'rb').read())
