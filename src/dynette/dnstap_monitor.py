#!/usr/bin/env python

import argparse
import datetime
import os
import socket
from pathlib import Path

import dns.message

from .config import Config
from .dynette import Dynette
from .shodohflo.fstrm import Consumer, Server, UnixSocket
from .shodohflo.protobuf import dnstap

# SHODOHFLO_DIR = Path(__file__).resolve().parent.parent.parent.parent / "shodohflo"
# sys.path.insert(0, str(SHODOHFLO_DIR))
# print(SHODOHFLO_DIR)


def hexify(data: bytes) -> str:
    return "".join(f"{byte:02x} " for byte in data)


class DnsData:
    def __init__(self, dynette: Dynette, zones: list[str]) -> None:
        self.zones = zones
        self.domain_times: dict[str, int] = {}
        self.counter = 0

        self.dynette = dynette
        self.save_interval = datetime.timedelta(minutes=15)
        self._last_save: datetime.datetime | None = None

    def update(self, domain: str, time_s: int) -> None:
        if not any(domain.endswith(zone) for zone in self.zones):
            return
        self.domain_times[domain] = time_s
        self.counter += 1
        self.save(force=False)

    def save(self, *, force: bool = False) -> None:
        now = datetime.datetime.now(tz=datetime.UTC)
        if not force and self._last_save and now - self._last_save < self.save_interval:
            return

        update_count = 0
        updated = self.dynette.set_last_query(self.domain_times)
        update_count += updated
        self.domain_times.clear()
        self._last_save = now
        print(
            f"Data saved on {now}, {update_count} updates, {self.counter} since startup"
        )


class DnsTap(Consumer):
    def __init__(self, data: DnsData, zones: list[str]) -> None:
        self.data = data
        self.zones = zones
        super().__init__()

    def accepted(self, data_type: str) -> bool:
        print(f"Accepting: {data_type}")
        return True

    def consume(self, frame: bytes) -> bool:
        """Where it all happens.

        One debugging trick is to set the return value to False, which will exit
        The loop. Don't forget to call server.socket.close() and allocate a new
        Server() before calling server.listen() again.
        """
        # print(f"Data:\n{hexify(frame)}")
        try:
            self.protobuf = dnstap.Dnstap(frame, log_wire_type=False)
            message: dnstap.Message = self.protobuf.field("message")[1]
            try:
                query: dns.message.QueryMessage = message.field("query_message")[1]
            except KeyError:
                # No query
                return True

            if query is None:
                return True

            query_time: dns.message.QueryMessage = message.field("query_time_sec")[1]

            questions: list = query.question
            for question in questions:
                domain = str(question).split()[0].removesuffix(".")
                self.data.update(domain, query_time)
        except Exception as e:
            print(f"Error: {e}")
            return True

        return True

    def finished(self, partial_frame: bytes) -> None:
        print(f'Finished. Partial data: "{hexify(partial_frame)}"')


class SystemDOrPathUnixSocket(UnixSocket):
    def get_socket(self) -> socket.socket:
        # First try to find the SystemD socket...
        listen_fds = int(os.environ.get("LISTEN_FDS", "0"))
        if listen_fds >= 1:
            sock = socket.fromfd(3, socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return sock

        self.clean_path()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self.path))
        return sock


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, default=Path("config.yml"))
    args = parser.parse_args()
    config = Config(args.config)
    dynette = Dynette(config.database, config.tlds)
    dynette.init()

    socket_address = config.bind.dnstap_socket

    print("Starting...")
    data = DnsData(dynette, config.tlds)
    consumer = DnsTap(data, config.tlds)
    socket = SystemDOrPathUnixSocket(socket_address)
    Server(socket, consumer).listen()
    data.save(force=True)


if __name__ == "__main__":
    main()
