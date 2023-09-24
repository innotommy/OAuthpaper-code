#!/usr/bin/env bash

python3 generate-sites-files.py --sites $1
echo "Generated single JSON files for each site."

python3 merge-sites-files.py
echo "Merged single JSON files into a single one."
