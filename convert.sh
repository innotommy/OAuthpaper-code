#!/usr/bin/env bash

python generate-sites-files.py --sites lists/sites.csv
echo "Generated single JSON files for each site."

python merge-sites-files.py
echo "Merged single JSON files into a single one."
