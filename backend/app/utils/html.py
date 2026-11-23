from __future__ import annotations

import html as html_lib
import re

SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")


def strip_html(value: str) -> str:
    without_scripts = SCRIPT_STYLE_RE.sub(" ", value)
    return html_lib.unescape(TAG_RE.sub(" ", without_scripts))
