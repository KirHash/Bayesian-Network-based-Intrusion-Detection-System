"""Settings from a .env file next to the code, so they need not be typed into every terminal."""
import os
from pathlib import Path


def parse(text):
    """KEY=value lines; blank lines and # comments are skipped, matching quotes are removed."""

    values = {}

    for line in text.splitlines():

        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, _, value = line.partition("=")

        key, value = key.strip().removeprefix("export ").strip(), value.strip()

        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]

        if key:
            values[key] = value

    return values


def load(path=None, environ=os.environ):
    """Put the file's settings into the environment. Real environment variables win."""

    path = Path(path) if path else Path(__file__).parent / ".env"

    if not path.is_file():
        return []

    added = []

    for key, value in parse(path.read_text(encoding="utf-8-sig")).items():

        if key not in environ:
            environ[key] = value
            added.append(key)

    return added
