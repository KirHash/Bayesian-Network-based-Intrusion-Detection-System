"""
Keeps the most recent log lines in memory so the dashboard can show them,
for people who have no terminal open on the server.
"""
import logging
import threading
from collections import deque
from datetime import datetime

CAPACITY = 2000

# one line per page poll would drown everything else
NOISY = ("uvicorn.access",)


class RingHandler(logging.Handler):

    def __init__(self, capacity=CAPACITY):

        super().__init__(level=logging.INFO)

        self.records = deque(maxlen=capacity)

        self.counter = 0

        self.guard = threading.Lock()

    def emit(self, record):

        if record.name in NOISY:
            return

        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)

        with self.guard:

            self.counter += 1

            self.records.append({
                "n": self.counter,
                "time": datetime.fromtimestamp(record.created).isoformat(timespec="seconds"),
                "level": record.levelname,
                "logger": record.name,
                "message": message
            })

    def recent(self, limit=300, minimum="INFO", after=0):
        """Newest last; `after` is the highest line number already seen."""

        floor = logging.getLevelName(minimum)

        with self.guard:

            lines = [
                r for r in self.records
                if r["n"] > after and logging.getLevelName(r["level"]) >= floor
            ]

        return lines[-limit:]


HANDLER = RingHandler()


def install():
    """Attach to the root logger (once) and capture Python warnings."""

    root = logging.getLogger()

    if HANDLER not in root.handlers:
        root.addHandler(HANDLER)

    if root.level == logging.WARNING or root.level == logging.NOTSET:
        root.setLevel(logging.INFO)

    logging.captureWarnings(True)

    return HANDLER
