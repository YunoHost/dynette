#!/usr/bin/env python3

import argparse
import datetime
from pathlib import Path

from dynette.config import Config
from dynette.dynette import Dynette


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, default=Path("config.yml"))
    args = parser.parse_args()

    config = Config(args.config)
    dynette = Dynette(config.database, config.tlds)

    config_file: Path = args.config
    assert config_file.is_file()

    for domain, last_query in dynette.iter_last_queries():
        date = datetime.datetime.fromtimestamp(last_query, tz=datetime.UTC)
        delta = datetime.datetime.now(tz=datetime.UTC) - date
        # print(domain, date)

        if delta > datetime.timedelta(days=30):
            print(f"{domain} not requested for {delta.days} days")


if __name__ == "__main__":
    main()
