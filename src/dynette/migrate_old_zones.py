#!/usr/bin/env python3

import argparse
from collections import defaultdict
from pathlib import Path

import jinja2
import zonefile_parser
from zonefile_parser.record import Record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=Path, required=True)
    parser.add_argument("-o", "--output-dir", type=Path, required=True)
    parser.add_argument("-t", "--tld", type=str, required=True)
    args = parser.parse_args()

    input_file: Path = args.input
    output_dir: Path = args.output_dir
    output_dir.mkdir(exist_ok=True)

    suffix = f".{args.tld}."
    domains: dict[str, list[Record]] = defaultdict(list)

    records = zonefile_parser.parse(input_file.read_text())
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
        outfile = output_dir / f"{domain}.{args.tld}.db"
        template = template_environ.get_template("zone.db.j2")

        with outfile.open("w") as stream:
            stream.write(template.render(domain=f"{domain}.{args.tld}"))
            for record in records:
                # print(record)
                line = f"{record.name}\t{record.rtype}"
                assert record.rdata is not None
                match record.rtype:
                    case "SRV":
                        line += f" {record.rdata['priority']} {record.rdata['weight']} {record.rdata['port']} {record.rdata['host']}"
                    case "CAA":
                        line += f" {record.rdata['flag']} {record.rdata['tag']} {record.rdata['value']}"
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


if __name__ == "__main__":
    main()
