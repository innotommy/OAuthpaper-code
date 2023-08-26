#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2023 Matteo Golinelli"
__license__ = "MIT"

import argparse
import logging
import glob
import json
import csv
import os

'''
For each site crawled, generate a JSON file with the following structure:

{
    'site': '',
    'ranking': '',
    'loginpages': [{
        'loginpage': '',
        'SSOs': [
            {
                'provider': 'google',
                'attributes': [{
                    'name': 'class',
                    'value': 'grid--cell s-btn s-btnicon s-btngoogle bar-md ba bc-black-100'
                }, {
                    'name': 'data-oauthserver',
                    'value': 'https://accounts.google.com/o/oauth2/auth'
                }, {
                    'name': 'data-oauthversion',
                    'value': '2.0'
                }, {
                    'name': 'data-provider',
                    'value': 'google'
                }],
                'tag': 'button',
                'dompath': '//html/body/div[3]/div[2]/div[1]/div[2]/button[1]'
            }, ...
        ]
    }, ...
    ]
}
'''

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate JSON files for each site crawled.')

    parser.add_argument('-s', '--sites', help='Tranco ranking csv file', required=True)
    parser.add_argument('-d', '--debug', action='store_true', help='Verbose output')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if not os.path.exists('json'):
        os.makedirs('json')

    clean_dictionary = {
        'site': '',
        'ranking': '',
        'loginpages': []
    }

    tranco = {}

    with open(args.sites, 'r') as f:
        reader = csv.reader(f)

        for row in reader:
            tranco[row[1]] = int(row[0])

    for filename in glob.glob('links/*'):
        with open(filename, 'r') as f:
            links = json.load(f)

        output = clean_dictionary.copy()

        output['site'] = links['site']
        output['ranking'] = str(tranco[links['site']]) if links['site'] in tranco else '-1'
        output['loginpages'] = []
        if len(links['login']) > 0:
            for login in links['login']:
                idps_loginpage = links['login'][login]

                loginpage = {
                    'loginpage': login,
                    'SSOs': []
                }

                for provider in idps_loginpage:
                    data = {
                        'provider': provider
                    }
                    if 'xpath' in idps_loginpage[provider]:
                        data['xpath'] = idps_loginpage[provider]['xpath']
                    if 'tag' in idps_loginpage[provider]:
                        data['tag'] = idps_loginpage[provider]['tag']
                    if 'url' in idps_loginpage[provider]:
                        data['url'] = idps_loginpage[provider]['url']
                    loginpage['SSOs'].append(data)

            output['loginpages'].append(loginpage)

        with open('json/' + links['site'] + '.json', 'w') as f:
            json.dump(output, f, indent=4)

    logging.debug('Done.')
