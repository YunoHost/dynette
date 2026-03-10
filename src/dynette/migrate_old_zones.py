#!/usr/bin/env python3

import argparse
from pathlib import Path

import zonefile_parser


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=Path, required=True)
    parser.add_argument("-o", "--output-dir", type=Path, required=True)
    args = parser.parse_args()

    input_file = args.input
    records = zonefile_parser.parse(input_file.read_text())
    for record in records:
        print(record)

    # config = yaml.safe_load(args.config.open())
    # db_folder = Path(config["LEGACY_DB_FOLDER"])
    # output = args.output or Path(config["DB_PATH"])

if __name__ == "__main__":
    main()
