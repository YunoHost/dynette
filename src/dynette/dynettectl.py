#!/usr/bin/env python3

import argparse
from pathlib import Path

from .config import Config
from .dynette import Dynette


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    sub_add = sub.add_parser("add")
    sub_add.add_argument("domain")
    sub_add.add_argument("-k", "--key", type=str, required=True)
    sub_add.add_argument("-p", "--password", type=str)
    sub_del = sub.add_parser("delete")
    sub_del.add_argument("domain")
    sub_list = sub.add_parser("list")
    sub_list.add_argument("-t", "--tld", type=str, required=False)

    args = parser.parse_args()

    config = Config(args.config)
    dynette = Dynette(config.database, config.tlds)
    dynette.init()

    match args.action:
        case "add":
            dynette.register(args.domain, args.key, args.password)
        case "delete":
            dynette.delete(args.domain, None, None, bypass_auth=True)
        case "list":
            for domain in dynette.iter(args.tld):
                print(domain.name)


if __name__ == "__main__":
    main()
