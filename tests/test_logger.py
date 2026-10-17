import time
from datetime import datetime

import pytest

from main import Logger


LEVELS = [
    ("info", "INFO"),
    ("error", "ERROR"),
    ("debug", "DEBUG"),
    ("warning", "WARNING"),
    ("critical", "CRITICAL"),
]


@pytest.mark.parametrize(("method", "level"), LEVELS)
def test_each_level_prints_expected_prefix(capsys, method, level):
    logger = Logger(name="app")
    getattr(logger, method)("hello")

    assert capsys.readouterr().out.strip() == f"{level}: [app] hello"


def test_warning_is_not_misspelled(capsys):
    Logger().warning("careful")

    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "WARMING" not in out


def test_custom_formatting(capsys):
    logger = Logger(name="api", formatting="{level} | {name} | {text}")
    logger.error("boom")

    assert capsys.readouterr().out.strip() == "ERROR | api | boom"


def test_text_and_message_are_aliases(capsys):
    logger = Logger(formatting="{text}|{message}")
    logger.info("same")

    assert capsys.readouterr().out.strip() == "same|same"


def test_text_is_not_treated_as_a_format_string(capsys):
    Logger().info("{level}")

    assert capsys.readouterr().out.strip() == "INFO: [main] {level}"


def test_escaped_braces(capsys):
    Logger(formatting="{{log}}: {level}").info("x")

    assert capsys.readouterr().out.strip() == "{log}: INFO"


def test_iso_timestamp_is_timezone_aware(capsys):
    Logger(formatting="{iso_timestamp}").info("x")
    raw = capsys.readouterr().out.strip()

    parsed = datetime.fromisoformat(raw)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() is not None
    assert not raw.endswith("Z")


def test_date_and_time_match_iso_timestamp(capsys):
    Logger(formatting="{date}|{time}|{iso_timestamp}").info("x")
    date_part, time_part, iso_part = capsys.readouterr().out.strip().split("|")

    parsed = datetime.fromisoformat(iso_part)
    assert date_part == parsed.strftime("%d.%m.%Y")
    assert time_part == parsed.strftime("%H:%M:%S")


def test_unix_timestamp_is_seconds_since_epoch(capsys):
    before = int(time.time())
    Logger(formatting="{unix_timestamp}").info("x")
    after = int(time.time())

    value = int(capsys.readouterr().out.strip())
    assert before <= value <= after


def test_timestamp_field_is_a_datetime(capsys):
    Logger(formatting="{timestamp.year}").info("x")

    year = int(capsys.readouterr().out.strip())
    assert abs(year - datetime.now().year) <= 1


@pytest.mark.parametrize(
    "formatting",
    [
        "{unknown}",
        "{}",
        "{0}",
        "{unix_timestamp:%Y}",
        "{timestamp.nope}",
        "{statdart_timestamp}",
        "{",
    ],
)
def test_invalid_format_string_fails_fast(formatting):
    with pytest.raises(ValueError):
        Logger(formatting=formatting)


def test_valid_format_specs_are_accepted(capsys):
    Logger(formatting="{unix_timestamp:>12}|{timestamp:%Y-%m-%d}").info("x")
    unix_part, date_part = capsys.readouterr().out.strip().split("|")

    assert unix_part.strip().isdigit()
    assert date_part == datetime.now().strftime("%Y-%m-%d")
