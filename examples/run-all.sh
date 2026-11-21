#!/bin/sh
# Audit the sample inventory with grades, then run the tests.
set -e
cd "$(dirname "$0")/.."
python3 run.py samples/hosts.json --grade || true
python3 -m unittest discover -s tests -v
