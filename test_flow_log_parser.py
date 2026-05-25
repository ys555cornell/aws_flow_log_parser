# test_flow_log_parser.py

import io
import pytest

from flow_log_parser import (
    FlowLogParser,
    ConnectionTuple,
)


VALID_LOGS = """\
2 123 eni-1 10.0.0.1 10.0.0.2 12345 80 6 10 1000 100 200 ACCEPT OK
2 123 eni-1 10.0.0.1 10.0.0.3 12346 443 6 20 2000 100 200 ACCEPT OK
2 123 eni-1 10.0.0.2 10.0.0.4 53 5050 17 5 500 100 200 ACCEPT OK
"""


def make_stream(content: str):
    """
    Helper to build an in-memory file stream.
    """
    return io.StringIO(content)


# =========================================================
# Initialization / Validation Tests
# =========================================================

def test_valid_parser_initialization():
    parser = FlowLogParser(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port="12345",
        dst_port="80",
    )

    assert parser is not None


@pytest.mark.parametrize(
    "invalid_ip",
    [
        "999.999.999.999",
        "abc",
        "10.0.0",
        "",
    ]
)
def test_invalid_source_ip_raises(invalid_ip):
    with pytest.raises(ValueError):
        FlowLogParser(src_ip=invalid_ip)


@pytest.mark.parametrize(
    "invalid_port",
    [
        "-1",
        "65536",
        "abc",
        "22.5",
        "",
    ]
)
def test_invalid_source_port_raises(invalid_port):
    with pytest.raises(ValueError):
        FlowLogParser(src_port=invalid_port)


# =========================================================
# Basic Parsing Tests
# =========================================================

def test_parse_all_lines_without_filters():
    parser = FlowLogParser()

    results = list(
        parser.parse_and_filter(
            make_stream(VALID_LOGS)
        )
    )

    assert len(results) == 3


def test_filter_by_source_ip():
    parser = FlowLogParser(src_ip="10.0.0.1")

    results = list(
        parser.parse_and_filter(
            make_stream(VALID_LOGS)
        )
    )

    assert len(results) == 2

    for line in results:
        assert "10.0.0.1" in line


def test_filter_by_destination_ip():
    parser = FlowLogParser(dst_ip="10.0.0.4")

    results = list(
        parser.parse_and_filter(
            make_stream(VALID_LOGS)
        )
    )

    assert len(results) == 1

    assert "10.0.0.4" in results[0]


def test_filter_by_source_port():
    parser = FlowLogParser(src_port="53")

    results = list(
        parser.parse_and_filter(
            make_stream(VALID_LOGS)
        )
    )

    assert len(results) == 1

    assert " 53 " in results[0]


def test_filter_by_destination_port():
    parser = FlowLogParser(dst_port="443")

    results = list(
        parser.parse_and_filter(
            make_stream(VALID_LOGS)
        )
    )

    assert len(results) == 1

    assert " 443 " in results[0]


def test_filter_multiple_fields():
    parser = FlowLogParser(
        src_ip="10.0.0.1",
        dst_port="80",
    )

    results = list(
        parser.parse_and_filter(
            make_stream(VALID_LOGS)
        )
    )

    assert len(results) == 1

    assert "10.0.0.2" in results[0]


def test_no_matches():
    parser = FlowLogParser(src_ip="192.168.1.1")

    results = list(
        parser.parse_and_filter(
            make_stream(VALID_LOGS)
        )
    )

    assert results == []


# =========================================================
# Header / Empty Line Tests
# =========================================================

def test_skip_header_lines():
    logs = """\
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
2 123 eni-1 10.0.0.1 10.0.0.2 12345 80 6 10 1000 100 200 ACCEPT OK
"""

    parser = FlowLogParser()

    results = list(
        parser.parse_and_filter(
            make_stream(logs)
        )
    )

    assert len(results) == 1


def test_skip_empty_lines():
    logs = """\

2 123 eni-1 10.0.0.1 10.0.0.2 12345 80 6 10 1000 100 200 ACCEPT OK


"""

    parser = FlowLogParser()

    results = list(
        parser.parse_and_filter(
            make_stream(logs)
        )
    )

    assert len(results) == 1


# =========================================================
# Malformed Line Tests
# =========================================================

def test_skip_malformed_lines(capsys):
    logs = """\
bad line
2 123 eni-1 10.0.0.1 10.0.0.2 12345 80 6 10 1000 100 200 ACCEPT OK
"""

    parser = FlowLogParser()

    results = list(
        parser.parse_and_filter(
            make_stream(logs)
        )
    )

    captured = capsys.readouterr()

    assert len(results) == 1

    assert "Warning: malformed line" in captured.err


def test_malformed_lines_do_not_crash():
    logs = """\
too short
another bad line
"""

    parser = FlowLogParser()

    results = list(
        parser.parse_and_filter(
            make_stream(logs)
        )
    )

    assert results == []


# =========================================================
# Connection Count Tests
# =========================================================

def test_connection_counts_single_connection():
    logs = """\
2 123 eni-1 10.0.0.1 10.0.0.2 12345 80 6 10 1000 100 200 ACCEPT OK
2 123 eni-1 10.0.0.1 10.0.0.2 12345 80 6 15 1500 100 200 ACCEPT OK
"""

    parser = FlowLogParser()

    list(
        parser.parse_and_filter(
            make_stream(logs)
        )
    )

    counts = parser.get_connection_counts()

    expected = ConnectionTuple(
        src_ip="10.0.0.1",
        src_port="12345",
        dst_ip="10.0.0.2",
        dst_port="80",
        protocol="6",
    )

    assert counts[expected] == 2


def test_connection_counts_multiple_connections():
    parser = FlowLogParser()

    list(
        parser.parse_and_filter(
            make_stream(VALID_LOGS)
        )
    )

    counts = parser.get_connection_counts()

    assert len(counts) == 3

    assert sum(counts.values()) == 3


def test_connection_counts_respect_filters():
    parser = FlowLogParser(src_ip="10.0.0.1")

    list(
        parser.parse_and_filter(
            make_stream(VALID_LOGS)
        )
    )

    counts = parser.get_connection_counts()

    assert len(counts) == 2

    for conn in counts:
        assert conn.src_ip == "10.0.0.1"


# =========================================================
# Edge Case Tests
# =========================================================

def test_dash_values_are_handled():
    logs = """\
2 123 eni-1 10.0.0.1 10.0.0.2 - - 6 10 1000 100 200 ACCEPT OK
"""

    parser = FlowLogParser()

    results = list(
        parser.parse_and_filter(
            make_stream(logs)
        )
    )

    assert len(results) == 1


def test_large_port_numbers_boundary():
    logs = """\
2 123 eni-1 10.0.0.1 10.0.0.2 65535 0 6 10 1000 100 200 ACCEPT OK
"""

    parser = FlowLogParser()

    results = list(
        parser.parse_and_filter(
            make_stream(logs)
        )
    )

    assert len(results) == 1


def test_unicode_input_handled_by_ascii_open_not_parser():
    """
    Parser itself operates on streams.
    UnicodeDecodeError is tested at file-open level,
    not parser level.
    """
    parser = FlowLogParser()

    results = list(
        parser.parse_and_filter(
            make_stream(VALID_LOGS)
        )
    )

    assert len(results) == 3