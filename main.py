"""OmniLogex — a tiny dependency-free console logger."""

from datetime import datetime
from typing import Any, Dict, Optional

__all__ = ["Logger"]

DEFAULT_FORMAT = "{level}: [{name}] {text}"


class Logger:
    """A minimal console logger.

    Parameters
    ----------
    name:
        Name shown in the ``{name}`` placeholder.
    formatting:
        ``str.format`` template. Available placeholders: ``text``,
        ``message`` (alias for ``text``), ``name``, ``level``,
        ``unix_timestamp``, ``timestamp`` (timezone-aware ``datetime``),
        ``iso_timestamp``, ``date`` and ``time``.
    """

    def __init__(self, name: str = __name__, formatting: str = DEFAULT_FORMAT):
        self.name = name
        self.format_string = formatting
        self._validate_format()

    def _validate_format(self) -> None:
        """Fail fast on unknown placeholders or invalid format specs."""
        sample = self._build_record("message", "LEVEL")
        try:
            self.format_string.format(**sample)
        except (KeyError, IndexError, ValueError, AttributeError, TypeError) as exc:
            raise ValueError(
                f"Invalid format string {self.format_string!r}: {exc}"
            ) from exc

    def _build_record(
        self, text: str, level: str, now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        # Timezone-aware local time: ISO 8601 gets a real offset instead of
        # a misleading "Z" suffix that would claim the time is UTC.
        now = now if now is not None else datetime.now().astimezone()
        return {
            "text": text,
            "message": text,
            "name": self.name,
            "level": level,
            "unix_timestamp": int(now.timestamp()),
            "timestamp": now,
            "iso_timestamp": now.isoformat(),
            "date": now.strftime("%d.%m.%Y"),
            "time": now.strftime("%H:%M:%S"),
        }

    def _log(self, text: str, level: str) -> None:
        record = self._build_record(text, level)
        print(self.format_string.format(**record))

    def info(self, text: str) -> None:
        self._log(text, "INFO")

    def error(self, text: str) -> None:
        self._log(text, "ERROR")

    def debug(self, text: str) -> None:
        self._log(text, "DEBUG")

    def warning(self, text: str) -> None:
        self._log(text, "WARNING")

    def critical(self, text: str) -> None:
        self._log(text, "CRITICAL")
