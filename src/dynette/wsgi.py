#!/usr/bin/env python3

import logging

from .app import create_app

logger = logging.getLogger("gunicorn.error") if __name__ != "__main__" else None
app = create_app(logger=logger)

if __name__ == "__main__":
    app.run()
