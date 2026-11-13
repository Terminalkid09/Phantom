"""Standalone entry point used by PyInstaller and Electron."""

from phantom.api.server import main


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Phantom local API backend")
    parser.add_argument("--port", type=int, default=9876)
    args = parser.parse_args()
    main(args.port)
