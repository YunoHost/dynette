#!/usr/bin/env python3

import argparse
from collections import defaultdict
from pathlib import Path

import jinja2
import zonefile_parser
from zonefile_parser.record import Record

from .config import Config


def split_tld_into_zones(tld_file: Path, zones_dir: Path, tld: str) -> None:
    zones_dir.mkdir(exist_ok=True)

    suffix = f".{tld}."
    domains: dict[str, list[Record]] = defaultdict(list)

    records = zonefile_parser.parse(tld_file.read_text())
    print(f"Read {len(records)} records from file.")

    for record in records:
        subdomain: str = record.name.removesuffix(suffix).split(".")[-1]
        domains[subdomain].append(record)

    print(f"Groupped {len(records)} records into {len(domains)} domains.")

    templates_dir = Path(__file__).resolve().parent / "templates"
    template_loader = jinja2.FileSystemLoader(searchpath=templates_dir)
    template_environ = jinja2.Environment(
        loader=template_loader, keep_trailing_newline=True
    )

    for domain, records in domains.items():
        if not domain:
            continue
        outfile = zones_dir / f"{domain}.{tld}.db"
        template = template_environ.get_template("zone.db.j2")

        with outfile.open("w") as stream:
            stream.write(template.render(domain=f"{domain}.{tld}"))
            for record in records:
                # print(record)
                line = f"{record.name}\t{record.rtype}"
                assert record.rdata is not None
                match record.rtype:
                    case "SRV":
                        line += f" {record.rdata['priority']} {record.rdata['weight']}"
                        line += f" {record.rdata['port']} {record.rdata['host']}"
                    case "CAA":
                        line += f" {record.rdata['flag']} {record.rdata['tag']}"
                        line += f" {record.rdata['value']}"
                    case "MX":
                        line += f" {record.rdata['priority']} {record.rdata['host']}"
                    case "TXT":
                        line += f' "{record.rdata["value"]}"'
                    case "A" | "AAAA" | "CNAME":
                        line += f" {record.rdata['value']}"
                    case _:
                        raise RuntimeError(f"Unknown record {record}")
                stream.write(line)
                stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, default=Path("config.yml"))
    parser.add_argument("-i", "--input", type=Path)
    parser.add_argument("-o", "--output-dir", type=Path)
    parser.add_argument("-t", "--tld", type=str)
    args = parser.parse_args()

    if (args.config and any((args.input, args.output_dir, args.tld))) or (
        not args.config and not all((args.input, args.output_dir, args.tld))
    ):
        raise RuntimeError("Please only specify config or [input, output-dir, tld]!")

    if args.config:
        config = Config(args.config)
        for tld in config.tlds:
            tld_file = config.bind.database_dir / f"{tld}.db"
            zones_dir = config.bind.database_dir / tld
            split_tld_into_zones(tld_file, zones_dir, tld)

    else:
        split_tld_into_zones(args.input, args.output_dir, args.tld)


if __name__ == "__main__":
    main()
