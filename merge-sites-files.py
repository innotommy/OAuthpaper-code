#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2023 Matteo Golinelli"
__license__ = "MIT"

'''
Take all the single files in the json folder
and merge them into a list to dump in a single file
'''

import glob
import json

if __name__ == '__main__':
    json_files = glob.glob('json/*.json')

    data = []
    for json_file in json_files:
        with open(json_file) as f:
            data.append(json.load(f))

    with open('json/sites.json', 'w') as f:
        json.dump(data, f) # Note: no indentation here otherwise the file might get extremely big
