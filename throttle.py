"""A small in-memory limit on repeated failures from one source, e.g. guessing a token or a key."""
import time


class Throttle:
    """Refuses a key for a while after it has failed `limit` times within `window` seconds."""

    def __init__(self, limit=20, window=300, clock=time.time):

        self.limit = limit
        self.window = window
        self.clock = clock
        self.hits = {}

    def blocked(self, key):
        """Seconds until this key may try again, or 0."""

        now = self.clock()

        recent = [t for t in self.hits.get(key, []) if now - t < self.window]

        if recent:
            self.hits[key] = recent
        else:
            self.hits.pop(key, None)

        if len(recent) >= self.limit:
            return int(self.window - (now - recent[0])) + 1

        return 0

    def fail(self, key):
        """Record one failure. Returns True when this one reaches the limit."""

        now = self.clock()

        recent = [t for t in self.hits.get(key, []) if now - t < self.window] + [now]

        self.hits[key] = recent

        # keep the table from growing without bound under a flood of distinct sources
        if len(self.hits) > 10_000:
            for stale in [k for k, v in self.hits.items() if now - v[-1] >= self.window]:
                del self.hits[stale]

        return len(recent) == self.limit
