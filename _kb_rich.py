"""
_kb_rich.py — degraded stdlib drop-in for the rich API surface used by kitsunebi.

Covers:
  Console()  .print(str | Panel | Table)  .status(str) [context manager]
  Panel(content, *, title, border_style)
  Table(**kw)  .add_column(name, **kw)  .add_row(*cells)
  box.SIMPLE_HEAD  (sentinel constant — ignored in stub)

Output: plain text with rich markup tags stripped. ASCII borders for Panel/Table.
No external dependencies — pure Python stdlib.
"""

import re
import shutil

# Strip all rich markup tags: [bold], [red], [/bold cyan], etc.
_MARKUP = re.compile(r"\[/?[^\]\[]*\]")


def _strip(text: str) -> str:
    return _MARKUP.sub("", str(text))


def _term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


# ── Context manager returned by Console.status() ──────────────────────────────

class _StatusCtx:
    def __init__(self, msg: str):
        print(_strip(msg) + "...")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    # rich's status object supports .update() in some call sites
    def update(self, msg: str):
        print(_strip(msg) + "...")


# ── Panel ─────────────────────────────────────────────────────────────────────

class Panel:
    def __init__(self, content, *, title: str = "", border_style: str = ""):
        self._content = content
        self._title   = _strip(title)

    def _render(self, width: int):
        inner = width - 4  # 2 chars border + 1 space each side
        lines = _strip(str(self._content)).splitlines() if self._content else []

        title_str = f"[ {self._title} ]" if self._title else ""
        top_fill  = max(0, inner - len(title_str))
        top       = "+" + "-" * 2 + title_str + "-" * top_fill + "-+"

        print(top[:width])
        for line in lines:
            # wrap long lines
            while len(line) > inner:
                print("| " + line[:inner] + " |")
                line = line[inner:]
            print("| " + line.ljust(inner) + " |")
        print("+" + "-" * (width - 2) + "+")


# ── Table ─────────────────────────────────────────────────────────────────────

class Table:
    def __init__(self, title: str = "", **_kw):
        self._title = _strip(title)
        self._cols: list[str] = []
        self._rows: list[tuple] = []

    def add_column(self, name: str, **_kw):
        self._cols.append(_strip(name))

    def add_row(self, *cells):
        self._rows.append(tuple(_strip(str(c)) for c in cells))

    def _render(self, width: int):
        if self._title:
            print(f"\n  {self._title}")

        if not self._cols:
            return

        # Compute column widths: max of header and all cell values, capped so total <= width
        n = len(self._cols)
        col_w = [len(h) for h in self._cols]
        for row in self._rows:
            for i, cell in enumerate(row):
                if i < n:
                    col_w[i] = max(col_w[i], len(str(cell)))

        # Scale down proportionally if too wide
        total = sum(col_w) + 3 * n + 1  # borders + padding
        if total > width:
            scale = (width - 3 * n - 1) / max(sum(col_w), 1)
            col_w = [max(4, int(w * scale)) for w in col_w]

        sep = "+" + "+".join("-" * (w + 2) for w in col_w) + "+"
        def row_line(cells):
            parts = []
            for i, w in enumerate(col_w):
                val = str(cells[i]) if i < len(cells) else ""
                parts.append(f" {val[:w].ljust(w)} ")
            return "|" + "|".join(parts) + "|"

        print(sep)
        print(row_line(self._cols))
        print(sep)
        for row in self._rows:
            print(row_line(row))
        print(sep)


# ── Console ───────────────────────────────────────────────────────────────────

class Console:
    def print(self, obj=None, *args, **_kw):
        width = _term_width()
        if isinstance(obj, Panel):
            obj._render(width)
        elif isinstance(obj, Table):
            obj._render(width)
        else:
            # Combine positional args the same way rich does
            parts = [obj] + list(args) if obj is not None else list(args)
            print(_strip(" ".join(str(p) for p in parts)))

    def status(self, msg: str) -> _StatusCtx:
        return _StatusCtx(msg)

    def rule(self, title: str = "", **_kw):
        width = _term_width()
        t = _strip(title)
        if t:
            pad = max(0, (width - len(t) - 2) // 2)
            print("-" * pad + " " + t + " " + "-" * pad)
        else:
            print("-" * width)


# ── box sentinel ──────────────────────────────────────────────────────────────

class _Box:
    """Sentinel namespace — stub ignores box style, all tables use same layout."""
    SIMPLE_HEAD  = None
    SIMPLE       = None
    MINIMAL      = None
    ROUNDED      = None
    HEAVY        = None
    DOUBLE       = None
    MARKDOWN     = None


box = _Box()
