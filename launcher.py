#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2023 Matteo Golinelli"
__license__ = "MIT"

from time import sleep

import subprocess
import traceback
import argparse
import logging
import random
import shlex
import json
import sys
import os

MAX = 5 # Max number of processes to run at once
crawler = 'idps-identification.py'

# Tested sites
tested = []

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='launcher.py', description='Launch the crawler on a list of sites')

    parser.add_argument('-s', '--sites',
        help='Sites list', required=True)
    parser.add_argument('-m', '--max',        default=MAX,
        help=f'Maximum number of sites to test concurrently (default: {MAX})')
    parser.add_argument('-a', '--arguments',  default='',
        help='Additional arguments to pass to the crawler (use with = sign: -a="--arg1 --arg2")')
    parser.add_argument('-t', '--testall',    default=False,
        help='Test also already tested sites', action='store_true')
    parser.add_argument('-c', '--crawler',    default=crawler,
        help='Alternative crawler script name to launch')
    parser.add_argument('-d', '--debug',      action='store_true',
        help='Enable debug mode')    

    args = parser.parse_args()

    if args.max:
        MAX = int(args.max)

    logging.basicConfig()
    logger = logging.getLogger('launcher')
    logger.setLevel(logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    # Retrieve already tested sites from tested.json file
    if not args.testall and os.path.exists(f'logs/tested.json'):
        with open(f'logs/tested.json', 'r') as f:
            tested = json.load(f)

    if len(tested) > 0:
        random.shuffle(tested)
        logger.info(f'Already tested sites ({len(tested)}): {", ".join(tested[:min(len(tested), 10)])}' +
            f'... and {len(tested) - min(len(tested), 10)} more')

    blacklist = ['google', 'facebook', 'amazon', 'twitter', '.gov', 'acm.com', 'jstor.org', 'arxiv']

    sites = []
    try:
        with open(args.sites, 'r') as f:
            sites = [s.strip() for s in f.readlines()]

        random.shuffle(sites)

        processes = {}

        for site in sites:
            if any(i in site for i in blacklist):
                continue
            try:
                rank = int(site.strip().split(',')[0])
                site = site.strip().split(',')[1]

                first = True # Execute the loop the first time regardless
                # Loop until we have less than MAX processes running
                while len(processes) >= MAX or first:
                    first = False

                    for s in processes.keys():
                        state = processes[s].poll()

                        if state is not None: # Process has finished
                            del processes[s]
                            logger.info(f'[{len(tested)}/{len(sites)} ({len(tested)/len(sites)*100:.2f}%)] {s} tested, exit-code: {state}.')
                            if state == 0:
                                tested.append(s)
                                with open(f'logs/tested.json', 'w') as f:
                                    json.dump(tested, f)
                            break
                    sleep(1)

                if site in tested and not args.testall:
                    continue

                # When we have less than MAX processes running, launch a new one
                if site != '' and site not in tested:
                    cmd  = f'python3 {args.crawler} -t {site} {args.arguments}'
                    logger.info(f'Testing {site}')
                    try:
                        # p = subprocess.Popen(shlex.split(cmd))
                        # processes[site] = p

                        p = subprocess.Popen(shlex.split('python3 sleep-print.py ' + site))
                        processes[site] = p

                        print('\t\t >>>', cmd)
                    except subprocess.TimeoutExpired as e:
                        logger.error(f'Timeout expired for {site}')
                    except subprocess.CalledProcessError as e:
                        logger.error(f'Could not test site {site}')
                    except Exception as e:
                        logger.error(f'Could not test site {site}')
                        traceback.print_exc()
            except Exception as e:
                logger.error(f'Error [{site}] {e}')
                traceback.print_exc()
    except KeyboardInterrupt:
        logger.error('Keyboard interrupt')
    except:
        logger.error(traceback.format_exc())
    finally:
        logger.info(f'Tested sites ({len(tested)}): {", ".join(tested[:min(len(tested), 10)])}' +
            f'... and {len(tested) - min(len(tested), 10)} more')
        with open(f'logs/tested.json', 'w') as f:
            json.dump(tested, f)
