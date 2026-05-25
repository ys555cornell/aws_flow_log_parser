import argparse
import ipaddress
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import TextIO, Dict, Tuple, Iterator, Optional


@dataclass(frozen=True)
class ConnectionTuple:
    """
    Represents a network connection 5-tuple:
    (source IP, source port, destination IP, destination port, protocol)
    """
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    protocol: str


class FlowLogParser:
    """
    Parses and filters AWS VPC Flow Logs.

    Expected AWS VPC Flow Log format (default v2):
    <version> <account-id> <interface-id> <srcaddr> <dstaddr>
    <srcport> <dstport> <protocol> <packets> <bytes>
    <start> <end> <action> <log-status>

    Reference:
    https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
    """

    # Field indices for standard AWS VPC Flow Log format
    SRC_IP_IDX = 3
    DST_IP_IDX = 4
    SRC_PORT_IDX = 5
    DST_PORT_IDX = 6
    PROTO_IDX = 7

    MIN_FIELDS = 14

    def __init__(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[str] = None,
        dst_port: Optional[str] = None,
    ):
        """
        Initialize parser with optional filtering criteria.
        """

        self._validate_ip(src_ip, "Source IP")
        self._validate_ip(dst_ip, "Destination IP")

        self._validate_port(src_port, "Source Port")
        self._validate_port(dst_port, "Destination Port")

        self.filters = {
            self.SRC_IP_IDX: src_ip,
            self.DST_IP_IDX: dst_ip,
            self.SRC_PORT_IDX: src_port,
            self.DST_PORT_IDX: dst_port,
        }

        # Remove unset filters
        self.filters = {
            idx: value for idx, value in self.filters.items()
            if value is not None
        }

        # Store 5-tuple connection counts
        self.connection_counts: Dict[ConnectionTuple, int] = defaultdict(int)

    @staticmethod
    def _validate_ip(ip: Optional[str], field_name: str) -> None:
        """
        Validate IPv4 address.
        """
        if ip is None:
            return

        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            raise ValueError(f"{field_name} '{ip}' is not a valid IPv4 address.")

    @staticmethod
    def _validate_port(port: Optional[str], field_name: str) -> None:
        """
        Validate TCP/UDP port.
        """
        if port is None:
            return
        
        if port == "-":
            return
        
        if not port.isdigit():
            raise ValueError(f"{field_name} '{port}' is not numeric.")

        port_num = int(port)

        if not (0 <= port_num <= 65535):
            raise ValueError(
                f"{field_name} '{port}' is outside valid range 0-65535."
            )

    def parse_and_filter(self, file_stream: TextIO) -> Iterator[str]:
        """
        Parse the flow log file line-by-line.

        Yields:
            Matching log lines as strings.

        Side Effects:
            Updates connection_counts for matching entries.
        """

        for line_num, line in enumerate(file_stream, start=1):
            stripped_line = line.strip()

            # Skip empty lines
            if not stripped_line:
                continue

            # Skip headers
            if stripped_line.startswith(("version", "account-id")):
                continue

            parts = stripped_line.split()

            # Validate minimum field count
            if len(parts) < self.MIN_FIELDS:
                print(
                    (
                        f"Warning: malformed line {line_num}: "
                        f"expected at least {self.MIN_FIELDS} fields, "
                        f"got {len(parts)}"
                    ),
                    file=sys.stderr,
                )
                continue

            # Apply filters
            if not all(
                parts[idx] == expected
                for idx, expected in self.filters.items()
            ):
                continue

            # Build 5-tuple
            conn = ConnectionTuple(
                src_ip=parts[self.SRC_IP_IDX],
                src_port=parts[self.SRC_PORT_IDX],
                dst_ip=parts[self.DST_IP_IDX],
                dst_port=parts[self.DST_PORT_IDX],
                protocol=parts[self.PROTO_IDX],
            )

            # Update counts
            self.connection_counts[conn] += 1

            yield stripped_line

    def get_connection_counts(self) -> Dict[ConnectionTuple, int]:
        """
        Return aggregated 5-tuple connection counts.
        """
        return dict(self.connection_counts)


def build_argument_parser() -> argparse.ArgumentParser:
    """
    Build CLI argument parser.
    """

    parser = argparse.ArgumentParser(
        description="Parse and filter AWS VPC Flow Logs."
    )

    parser.add_argument(
        "file_path",
        help="Path to ASCII flow log file"
    )

    parser.add_argument(
        "--src-ip",
        help="Filter by source IPv4 address"
    )

    parser.add_argument(
        "--dst-ip",
        help="Filter by destination IPv4 address"
    )

    parser.add_argument(
        "--src-port",
        help="Filter by source port"
    )

    parser.add_argument(
        "--dst-port",
        help="Filter by destination port"
    )

    parser.add_argument(
        "--show-counts",
        action="store_true",
        help="Display aggregated 5-tuple connection counts"
    )

    return parser


def main() -> None:
    """
    CLI entry point.
    """

    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        flow_parser = FlowLogParser(
            src_ip=args.src_ip,
            dst_ip=args.dst_ip,
            src_port=args.src_port,
            dst_port=args.dst_port,
        )

        with open(args.file_path, "r", encoding="ascii") as file_stream:
            for matching_line in flow_parser.parse_and_filter(file_stream):
                print(matching_line)

    except FileNotFoundError:
        print(
            f"Error: file '{args.file_path}' not found.",
            file=sys.stderr,
        )
        sys.exit(1)

    except UnicodeDecodeError:
        print(
            (
                f"Error: file '{args.file_path}' contains "
                "non-ASCII characters."
            ),
            file=sys.stderr,
        )
        sys.exit(1)

    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.show_counts:
        print("\n--- Connection Counts ---")

        counts = flow_parser.get_connection_counts()

        if not counts:
            print("No matching connections found.")
            return

        for conn, count in counts.items():
            print(
                f"Src: {conn.src_ip}:{conn.src_port} -> "
                f"Dst: {conn.dst_ip}:{conn.dst_port} "
                f"[Proto: {conn.protocol}] | Count: {count}"
            )


if __name__ == "__main__":
    main()