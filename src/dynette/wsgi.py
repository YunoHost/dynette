#!/usr/bin/env python3

from .app import create_app

if __name__ == "__main__":
    app = create_app()
    app.run()
