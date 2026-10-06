"""Re-time an asciicast so it plays well as a looping README animation.

rich prints each table in a single burst, so a raw recording shows long
pauses followed by whole screens appearing at once, and the final screen
disappears as soon as the loop restarts. This keeps the typing rhythm, spaces
program output out evenly, and holds the last frame.

The commands and their output are real and untouched; only the pacing changes.

Usage:
    python assets/retime.py <in.cast> <out.cast> [step seconds] [hold seconds]
"""

import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
step = float(sys.argv[3]) if len(sys.argv) > 3 else 0.12
hold = float(sys.argv[4]) if len(sys.argv) > 4 else 8.0

lines = source.read_text().splitlines()
header = json.loads(lines[0])
events = [json.loads(line) for line in lines[1:]]


def is_keystroke(payload: str) -> bool:
    """Typed characters arrive one at a time without a newline."""
    return "\n" not in payload and len(payload) <= 2


clock = 0.5
previous = events[0][0]
retimed = []
for time, kind, payload in events:
    gap = time - previous
    previous = time
    if is_keystroke(payload):
        clock += gap
    else:
        clock += min(max(gap, step), 2.0)
    retimed.append([round(clock, 3), kind, payload])

retimed.append([round(clock + hold, 3), "o", ""])
header.pop("idle_time_limit", None)
output = [json.dumps(header)] + [json.dumps(event) for event in retimed]
destination.write_text("\n".join(output) + "\n")
print(f"{len(retimed)} events, {clock + hold:.1f} s")
