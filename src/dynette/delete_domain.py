#!/usr/bin/env python3

import argparse
import sys
from collections.abc import Generator, Iterator
from pathlib import Path
from typing import TextIO, TypeVar

from .config import Config

T = TypeVar("T")


class RollableIterator[T]:
    def __init__(self, iterable: Iterator[T]) -> None:
        self._iterator = iter(iterable)
        self._last: T | None = None
        self._rolled_back: bool = False

    def __iter__(self) -> Iterator[T | None]:
        return self

    def __next__(self) -> T | None:
        if self._rolled_back and self._last is not None:
            self._rolled_back = False
            return self._last
        self._last = next(self._iterator, None)
        return self._last

    def undo(self) -> None:
        self._rolled_back = True


class ZoneParser:
    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self.lines: RollableIterator[str] = RollableIterator(self.stream)

    def parse_header(self) -> Generator[str]:
        for line in self.lines:
            if line is None:
                return
            yield line
            if "IN SOA" in line:
                self.tld = line.split()[0].removesuffix(".")
                break
        for line in self.lines:
            if line is None:
                return
            yield line
            if line.strip() == ")":
                break
        for line in self.lines:
            if line is None:
                return
            if line.startswith("$"):
                yield line
                continue
            if line.strip().startswith("NS\t") or line.strip().startswith("NS "):
                yield line
                continue
            self.lines.undo()
            break

    def next_domain(self) -> Generator[str]:
        line = next(self.lines)
        if line is None:
            return
        self.domain = line.split()[0]
        yield line

        for line in self.lines:
            if line is None:
                return
            if line.startswith("$TTL"):
                yield line
                continue
            if not line.startswith("\t"):
                next_domain = line.split()[0]
                if not next_domain.endswith(self.domain):
                    self.lines.undo()
                    break
            yield line

    def del_domain(self, domain: str) -> list[str]:
        lines = []
        lines.extend(self.parse_header())
        while True:
            next_lines = list(self.next_domain())
            if not next_lines:
                break
            if self.domain.removesuffix(".") != domain:
                lines.extend(next_lines)

        return lines



def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, default=Path("config.yml"))
    parser.add_argument("-d", "--domain", type=str, required=True)
    args = parser.parse_args()

    domain: str = args.domain
    config = Config(args.config)

    tlds = [tld for tld in config.tlds if domain.endswith(f".{tld}")]
    if len(tlds) != 1:
        print(f"Could not determine TLD for domain {domain} in tlds {config.tlds}!")
        sys.exit(1)
    tld = tlds[0]
    named_file = config.bind.database_dir / f"{tld}.db"
    new_named_file = config.bind.database_dir / f"{tld}.db.new"

    parser = ZoneParser(named_file.open())
    new_named_file.open("w").writelines(parser.del_domain(domain))


if __name__ == "__main__":
    main()
