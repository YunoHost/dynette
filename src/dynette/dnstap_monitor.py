#!/usr/bin/env python
# Copyright (c) 2019 by Fred Morris Tacoma WA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A sample program for the adventurously inclined.

This program is intended to read the Unix Domain socket written to by BIND.
You should ensure that SOCKET_ADDRESS points to the place where BIND is
configured to find it.

You can simply run it, or you can use it by:

    cd <this directory>
    python3
    >>> from tap_example import Server, UnixSocket, SOCKET_ADDRESS, DnsTap
    >>> tap = DnsTap()
    >>> server = Server(UnixSocket(SOCKET_ADDRESS), tap)
    >>> server.listen()
    ...
    ^C
    KeyboardInterrupt
    >>> server.sock.close()
    >>> tap.protobuf.field('message')[1].field('query_address')
    (Protobuf field: <class 'shodohflo.protobuf.dnstap.IpAddressField'>, IPv4Address('127.0.0.1'))
    >>> resp = tap.protobuf.field('message')[1].field('response_message')[1]
    >>> resp
    <DNS message, ID 5387>
    >>> type(resp)
    <class 'dns.message.Message'>
    >>> resp.question
    [<DNS www.cnn.com. IN A RRset>]
    >>> resp.answer
    [<DNS www.cnn.com. IN CNAME RRset>, <DNS turner-tls.map.fastly.net. IN A RRset>]

"""

import argparse
import pickle
import re
from datetime import datetime, timedelta
from pathlib import Path

from .config import Config
from .shodohflo.fstrm import Consumer, Server, UnixSocket
from .shodohflo.protobuf import dnstap

# SHODOHFLO_DIR = Path(__file__).resolve().parent.parent.parent.parent / "shodohflo"
# sys.path.insert(0, str(SHODOHFLO_DIR))
# print(SHODOHFLO_DIR)


def hexify(data: bytes) -> str:
    return "".join(f"{byte:02x} " for byte in data)


class DnsData(dict):
    def __init__(self, path: Path, zones: list[str]) -> None:
        self.path = path
        self.zones = zones
        self.save_interval = timedelta(minutes=15)
        self._last_save: datetime | None = None
        super().__init__()
        self._load()

    def _load(self) -> None:
        def _default_data() -> dict[str, dict]:
            return {zone: {} for zone in self.zones}

        if self.path.exists():
            try:
                data = pickle.load(self.path.open("rb"))
                if len(data) == 0:
                    data = _default_data()
            except (OSError, pickle.PickleError):
                data = _default_data()
        else:
            data = _default_data()
        self.clear()
        super().update(data)

        print(f"Data loaded on {datetime.now()} with {self._zones_str()}")

    def _zones_str(self) -> list[str]:
        return [f"{zone}: {len(self[zone])} entries" for zone in self.zones]

    def save(self, *, force: bool = False) -> None:
        now = datetime.now()

        if not force and self._last_save and now - self._last_save < self.save_interval:
            return

        self.path.parent.mkdir(parents=True, exist_ok=True)
        pickle.dump(dict(self), self.path.open("wb"), protocol=pickle.HIGHEST_PROTOCOL)

        self._last_save = now

        if len(self) != 0:
            print(f"Data saved on {now} with {self._zones_str()}")

    def _autosave_if_needed(self) -> None:
        self.save(force=False)

    def __setitem__(self, key, value) -> None:
        super().__setitem__(key, value)
        self._autosave_if_needed()

    def __delitem__(self, key) -> None:
        super().__delitem__(key)
        self._autosave_if_needed()

    def update(self, *args, **kwargs) -> None:
        super().update(*args, **kwargs)
        self._autosave_if_needed()

    def pop(self, *args) -> None:
        value = super().pop(*args)
        self._autosave_if_needed()
        return value

    def clear(self) -> None:
        super().clear()
        self._autosave_if_needed()


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
        # print('Data:\n{}'.format(hexify(frame)))
        try:
            self.protobuf = dnstap.Dnstap(frame, log_wire_type=False)

            message = str(self.protobuf.field("message")[1])
            # <Message type=TYPE_AUTH_RESPONSE socket_family=SOCKET_FAMILY_INET6
            #   socket_protocol=SOCKET_PROTOCOL_UDP
            #   query_address=2001:b000:180:8002:0:2:9:97
            #   response_address=2001:910:1400:115::13
            #   query_port=23626 response_port=1053
            #   query_zone=b'\x03ynh\x02fr\x00' response_time_sec=1766303014
            #   response_time_nsec=707127201 response_message=<
            #       status=NOERROR question=<rep-art.ynh.fr. IN AAAA> answer=<>
            #   |>
            # |>
            pattern = (
                ".* type=TYPE_AUTH_RESPONSE .* status=NOERROR question=<([\w\-\.]+) .*"
            )
            fqdn = re.findall(pattern, message)[0].lower()
            domain = None
            for zone in self.zones:
                escapedzone = zone.replace(".", r"\.")
                try:
                    finder = rf"[\w\-\.]*?([\w\-]+)\.{escapedzone}\."
                    domain = re.findall(finder, fqdn)[0]
                    now = datetime.now().replace(microsecond=0).isoformat()
                    self.data[zone].update({domain: now})
                    self.data.save()
                except Exception as e:
                    #                    print(f"Error: {e}, {finder} {fqdn} {domain}")
                    pass
        except Exception as e:
            print(f"Error: {e}")
            pass

        return True

    def finished(self, partial_frame: bytes) -> None:
        print(f'Finished. Partial data: "{hexify(partial_frame)}"')


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, default=Path("config.yml"))
    args = parser.parse_args()
    config = Config(args.config)

    pickle_db_path = config.dnstap.database
    socket_address = config.dnstap.socket

    print("Starting...")
    data = DnsData(pickle_db_path, config.tlds)
    consumer = DnsTap(data, config.tlds)
    Server(UnixSocket(socket_address), consumer).listen()
    data.save(force=True)


if __name__ == "__main__":
    main()
