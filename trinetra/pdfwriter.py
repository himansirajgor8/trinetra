"""Tiny dependency-free PDF writer (A4, base-14 fonts, text/rect/line). Runs anywhere Python runs - no reportlab.
Text is encoded as Windows-1252; characters outside it (e.g. Devanagari) are written as '?'."""
from __future__ import annotations
import zlib

W, H = 595.28, 841.89
FONTS = [("F1", "Helvetica"), ("F2", "Helvetica-Bold"), ("F3", "Courier"), ("F4", "Courier-Bold")]


def _txt(s: str) -> bytes:
    b = "".join(c if (c >= " " and c != "\x7f") else " " for c in s).encode("cp1252", "replace")
    return b.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def _c(rgb): return ("%.3f %.3f %.3f" % rgb).encode()


class PDF:
    def __init__(self, title="Document", author="Trinetra"):
        self.pages, self.cur, self.title, self.author = [], None, title, author

    def new_page(self):
        self.cur = []; self.pages.append(self.cur); return len(self.pages)

    def text(self, x, y, s, font="F3", size=9, color=(0, 0, 0)):
        self.cur.append(b"BT /" + font.encode() + b" %.2f Tf " % size + _c(color) + b" rg %.2f %.2f Td (" % (x, y) + _txt(s) + b") Tj ET")

    def rect(self, x, y, w, h, fill):
        self.cur.append(_c(fill) + b" rg %.2f %.2f %.2f %.2f re f" % (x, y, w, h))

    def line(self, x1, y1, x2, y2, color=(0.8, 0.8, 0.8), width=0.5):
        self.cur.append(_c(color) + b" RG %.2f w %.2f %.2f m %.2f %.2f l S" % (width, x1, y1, x2, y2))

    def page_count(self): return len(self.pages)

    def output(self) -> bytes:
        objs = [b""] * (3 + len(FONTS) + 2 * len(self.pages))   # 1 catalog, 2 pages, 3 info, fonts, then page/content pairs
        font_ids = {}; n = 4
        for key, name in FONTS:
            objs[n - 1] = b"<< /Type /Font /Subtype /Type1 /BaseFont /" + name.encode() + b" /Encoding /WinAnsiEncoding >>"; font_ids[key] = n; n += 1
        fres = b"<< /Font << " + b" ".join(b"/" + k.encode() + b" %d 0 R" % i for k, i in font_ids.items()) + b" >> >>"
        kids = []
        for pg in self.pages:
            page_id, cont_id = n, n + 1; n += 2
            data = zlib.compress(b"\n".join(pg))
            objs[cont_id - 1] = b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(data) + data + b"\nendstream"
            objs[page_id - 1] = (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources " % (W, H) + fres +
                                 b" /Contents %d 0 R >>" % cont_id)
            kids.append(page_id)
        objs[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
        objs[1] = b"<< /Type /Pages /Kids [" + b" ".join(b"%d 0 R" % k for k in kids) + b"] /Count %d >>" % len(kids)
        objs[2] = b"<< /Title (" + _txt(self.title) + b") /Author (" + _txt(self.author) + b") /Creator (Trinetra) >>"
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"); offsets = []
        for i, o in enumerate(objs, 1):
            offsets.append(len(out)); out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for off in offsets: out += b"%010d 00000 n \n" % off
        out += b"trailer\n<< /Size %d /Root 1 0 R /Info 3 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
        return bytes(out)
