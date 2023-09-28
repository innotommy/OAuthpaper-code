#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2023 Matteo Golinelli"
__license__ = "MIT"

from requests.exceptions import SSLError, ConnectionError, ReadTimeout
from urllib3.exceptions import NewConnectionError, MaxRetryError, ReadTimeoutError
from urllib.parse import urlparse, urlunparse, urljoin, urldefrag
from selenium import webdriver
from bs4 import BeautifulSoup

import traceback
import argparse
import requests
import logging
import random
import string
import json
import time
import sys
import os
import re

# =============================================================================
# =============================================================================
# ================================= FUNCTIONS =================================
# =============================================================================
# =============================================================================

# =============================================================================
# ========================= Basic crawling functions ==========================
# =============================================================================

def get_template_url(url, _path=True):
    """
    Returns the template of the passed URL. The template contains:
    - the netloc (domain)
    - the path (if path=True)
    Everything else is removed.
    """
    try:
        parsed = urlparse(urldefrag(url)[0])
        if _path:
            return urlunparse(('', parsed.netloc, parsed.path, '', '', ''))
        else:
            if len(parsed.path.split('/')) > 1:
                path = parsed.path.replace(parsed.path.split('/')[-1], '')
            else:
                path = parsed.path
            return urlunparse(('', parsed.netloc, re.sub('\d+', '', path), '', '', ''))
    except:
        logger.debug(traceback.format_exc())
        return None

def get_domain_name(url):
    """
    Returns the domain name of the passed URL
    (Ignore top level domain and subdomains).
    """
    try:
        if url.startswith('http') and '//' in url:
            parsed = urlparse(urldefrag(url)[0])
            split_netloc = parsed.netloc.replace('www.', '').split('.')
        else:
            split_netloc = url.split('.')
        if len(split_netloc) > 2:
            if len(split_netloc[-2]) >= 3:
                return split_netloc[-2]
            else:
                return split_netloc[-3]
        elif len(split_netloc) == 2:
            return split_netloc[-2]
        else:
            return ''
    except:
        logger.debug(url, split_netloc)
        logger.debug(traceback.format_exc())
        return None

def get_domain(url):
    """
    Returns the domain name of the passed URL.
    """
    return urlparse(url).netloc

def is_internal_url(url):
    """
    Returns True if the url is internal to the website.
    Ignores the top level domain:
    e.g., google.com and google.it are considered the same domain.
    """
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        parsed = urlparse(url)
        if get_domain_name(parsed.netloc).endswith(get_domain_name(SITE)):
            return True
        else:
            return False
    except:
        logger.error(traceback.format_exc())
        return False

def get_links(page_url, html, only_internal=True):
    """
    Receives a URL and the body of the web page
    and returns a set of all links found in the page
    if only_internal is True, only internal links are returned.
    """
    links = []

    try:
        soup = BeautifulSoup(html, 'html.parser')

        for link in soup.find_all('a', href=True):
            url = urljoin(clean_url(page_url), clean_url(link['href']))

            if 'http' in url and only_internal and is_internal_url(url):
                links.append(clean_url(urldefrag(url)[0]))

            elif not only_internal:
                _url = clean_url(urldefrag(url)[0])
                if any([i in _url for i in DENYLISTED_DOMAINS]):
                    continue

                links.append(_url)
    except:
        logger.debug(traceback.format_exc())

    return sorted(links)

def get_source_code_links(url, html):
    """
    Returns a list of all links found in the
    source code of the passed page.
    """

    cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()
    links = []

    # Find links in the source code using regular expressions
    regex_links = re.findall("((?:https?:\/\/|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}\/)(?:[^\s()<>\"\']+|\(([^\s()<>\"\']+|(\([^\s()<>\"\']+\)))*\))+(?:\(([^\s()<>\"\']+|(\([^\s()<>\"\']+\)))*\)|[^\s`!()\[\]{};:'\".,<>?]))", html)
    links = [''.join(link) for link in regex_links if not any([i in link for i in DENYLISTED_DOMAINS])]

    soup = BeautifulSoup(html, 'html.parser')
    # and in tags that have an href
    for link in soup.find_all(href=True):
        href = link['href']
        links.append(urljoin(url, href))
    # and in forms actions
    forms = soup.find_all('form')
    for form in forms:
        try:
            action = form.get('action')
            if action != None:
                links.append(urljoin(url, action))
        except:
            pass

    # and in buttons (action, href, data-url, data-href, ecc)
    buttons = soup.find_all('button')
    for button in buttons:
        try:
            action = urljoin(url, button.get('action'))
            if action != None:
                links.append(action)
        except:
            pass

    for button in buttons:
        try:
            data_url = button.get('data-url')
            if data_url != None:
                links.append(urljoin(url, data_url))
            data_href = button.get('data-href')
            if data_href != None:
                links.append(urljoin(url, data_href))
            formaction = button.get('formaction')
            if formaction != None:
                links.append(urljoin(url, formaction))
        except:
            pass
    
    return links

def add_to_queue(url, exclude_denylisted=True):
    """
    Add a url to the queue if it is not already in the queue
    and if its template is not already in the visited list.
    """
    try:
        if exclude_denylisted and any([i in url for i in DENYLISTED_PATTERNS]):
            return
        domain  = get_domain(url)

        if not is_visited(url):
            if domain not in queue:
                queue[domain] = []
            if url not in queue[domain]:
                queue[domain].append(url)
    except:
        if DEBUG:
            logger.error(traceback.format_exc())

def add_to_visited(url):
    """
    Add a url to the visited list.
    """
    try:
        if not is_visited(url):
            domain  = get_domain(url)
            if domain not in visited_urls:
                visited_urls[domain] = []

            template_url = get_template_url(url)
            visited_urls[domain].append(template_url)

    except:
        if DEBUG:
            logger.error(traceback.format_exc())

def is_visited(url):
    """
    Return True if the template of the url
    is in the visited list.
    """
    try:
        domain  = get_domain(url)
        if not domain in visited_urls:
            return False

        template_url = get_template_url(url)
        if template_url is not None and \
            template_url in visited_urls[domain]:
            return True
        else:
            return False
    except:
        if DEBUG:
            logger.error(traceback.format_exc())
    return False

def get_url_from_queue(visited=False):
    """
    Return the first not visited url in the queue
    if the visited list for this domain is not full.
    """
    domains = list(queue.keys())
    random.shuffle(domains)

    try:
        for domain in domains:
            # If the visited list for this domain
            # is full, choose a new domain
            if domain in visited_urls and \
                len(visited_urls[domain]) >= MAX:
                continue
            else:
                # Pop the first url in the queue
                # for this domain
                while len(queue[domain]) > 0:
                    url = queue[domain].pop(0)
                    if not is_visited(url):
                        if visited:
                            add_to_visited(url)
                        return url
    except:
        if DEBUG:
            logger.error(traceback.format_exc())
    return None

def should_continue():
    """
    Return True if the queue is not empty
    and the visited list is not full.
    """
    try:
        for domain in queue:
            if domain not in visited_urls or \
                (len(visited_urls[domain]) < MAX and \
                    len(queue[domain]) > 0):
                return True
    except:
        if DEBUG:
            logger.error(traceback.format_exc())
    return False

# =============================================================================
# ====================== Login detection functions ============================
# =============================================================================

def get_login_url(urls):
    """
    Return the login url from the list of urls (if present).
    """
    for url in urls:
        cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()
        # logger.info(f'{bcolors.OKGREEN}[+]{bcolors.ENDC} {url}')

        denylist = ['/hc/', 'facebook', 'google']

        if '/signin' in cleaned_url or \
            '/login' in cleaned_url and \
            '/join'  in cleaned_url and  \
            not any(i in cleaned_url for i in denylist):
            # logger.info(f'Login url found: {bcolors.OKGREEN}{url}{bcolors.ENDC} because contains /login or /signin')
            return url

    for url in urls:
        cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()

        if 'signin' in cleaned_url or \
            'login' in cleaned_url and \
            not any(i in cleaned_url for i in denylist):
            # logger.info(f'Login url found: {bcolors.OKGREEN}{url}{bcolors.ENDC} because contains login or signin')
            return url
    return ''

def is_login_page(url, html):
    """
    Return True if the current page is a login PAGE.
    """
    cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()

    if 'login' in cleaned_url or \
        'signin' in cleaned_url:
        return True
    
    soup = BeautifulSoup(html, 'html.parser')
    password = soup.find('input', {'type' : 'password'})
    if password is not None:
        return True
    return False

def get_oauth_link(urls, provider):
    """
    Return provider's OAuth link
    from a list of URLs
    """
    for url in urls:
        cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()
        denylist = [
            'itunes.apple', 'play.google', 'googleapis', 'googleads', 'doubleclick', 'googletagmanager.com', 'apis.google.com', '/hc/', 'assets', '.gif', '.jpeg', '.jpg', '.png', '.css', '.js',
            '/gsi/style', '/gsi/client', 'captcha', 'designing'
        ]

        denylisted_extensions = ['.gif', '.jpeg', '.jpg', '.png', '.css', '.js', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.otf', '.ico', '.xml', '.json', '.txt']
        parsed = urlparse(cleaned_url)
        if parsed.path.endswith(tuple(denylisted_extensions)):
            return ''

        # Expand denylist for specific providers
        denylist = extend_denylist(provider, denylist)

        if provider in cleaned_url and \
            not any(x in url for x in denylist) and \
            ( 'auth' in cleaned_url or \
                'login' in cleaned_url or\
                'account' in cleaned_url or\
                'signin' in cleaned_url ):
            return url
    return ''

def is_oauth_tag(tag, provider):
    """
    Return True if the tag is an OAuth login button
    """
    # Limit length
    if len(str(tag)) > 5000:
        return False

    combined = ''

    if type(tag.text) == str:
        combined += ';' + tag.text.strip().replace('\n', '')
    elif type(tag.text) == list:
        # ???
        logger.info(type(tag.text))
        logger.info(str(tag))
    for value in tag.attrs.values():
        if type(value) == str:
            combined += ';' + value.strip()
        elif type(value) == list:
            combined += ';' + '_'.join([x.strip() for x in value])
        else:
            #logger.info(type(value))
            #logger.info(str(tag))
            pass

    denylist = [
        'itunesapple', 'playgoogle', 'googleapis', 'googleads', 'doubleclick', 'googletagmanagercom', 'apisgooglecom',
        'captcha', 'designing']
    # Expand denylist for specific providers
    denylist = extend_denylist(provider, denylist)

    combined = combined.lower().replace('\n', '').replace('-', '').replace('.', '').replace('_', '').strip()
    while '  ' in combined:
        combined = combined.replace('  ', ' ')

    if (
        provider in combined and
        not any(x.replace('.', '') in combined for x in denylist) and
        any(x in combined for x in OAUTH_KEYWORDS)):
        return True

def get_oauth_tag(html, provider, all_tags=True):
    """
    Return the XPath to the OAuth login button
    """
    provider = provider.lower().strip()
    soup = BeautifulSoup(html, 'html.parser')

    # Begin with the most specific tags
    for tag in soup.find_all(["a", "input", "button"]):
        if is_oauth_tag(tag, provider):
            xpath = get_xpath(soup, tag)
            return str(tag), xpath

    if not all_tags:
        return None, None

    # Note: searching in less specific tags might increase the number of false positives
    for tag in soup.find_all():
        if tag.name in ["a", "input", "button", "script"]:
            continue
        if is_oauth_tag(tag, provider):
            xpath = get_xpath(soup, tag)
            return str(tag), xpath

    return None, None

# =============================================================================
# ============================= Helper functions ==============================
# =============================================================================

def get_random_string(start=10, end=20):
    return ''.join(random.choice(string.ascii_letters + string.digits + '_') for _ in range(random.randint(start, end)))

def clean_url(url):
    """
    Cleans the url to remove any trailing newlines and spaces.
    """
    return url.strip().strip('\n')

def url_to_filename(url):
    """
    Converts a URL to a filename.
    """
    template_url = get_template_url(url).split('.')[0] # Also remove the extension
    name = ''
    for c in template_url:
        if c in string.ascii_letters + string.digits:
            name += c
    return name

def extend_denylist(provider, denylist):
    '''
    Extend the denylist with specific
    patterns for the current provider.
    '''
    if provider == 'ok':
        denylist.extend(['facebook', 'token', 'cookie', 'Token'])
        # OK has a lot of false positives, so we also add all the other providers
        denylist.extend([provider.lower() for provider in PROVIDERS if provider.lower() != 'ok'])
    if provider == 'line':
        denylist.extend(['inline', 'streamline', 'guideline', 'offline', 'outline', 'online', 'underline', 'timeline', 'line-height', 'line-width'])
    if provider == 'google':
        denylist.extend(['playgooglecom', 'analytics', '/gsi/style'])
    if provider == 'amazon':
        denylist.extend(['amazonawscom'])
    if provider == 'stackoverflow':
        denylist.extend(['/question/'])
    if provider == 'facebook':
        denylist.extend(['sharerphp'])
    if provider == 'linkedin':
        denylist.extend(['share'])
    if provider == 'microsoft':
        denylist.extend(['jsdisabled'])
    if provider == 'reddit':
        denylist.extend(['submit'])
    if provider == 'yahoo':
        denylist.extend(['analytics'])
    if provider == 'twitter':
        denylist.extend(['intent'])

    return denylist

def remove_query_string(url):
    """
    Removes the query string from the url.
    """
    return url.split('?')[0]

def save_dictionaries(site, logs_dir):
    """
    Save the dictionaries to the files.
    """
    global urls, queue, visited_urls

    logs = {
        'queue':        queue,
        'visited':      visited_urls
    }
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    with open(f'{logs_dir}/{site}-log.json', 'w') as f:
        json.dump(logs, f, indent=4)
        logger.info(f'Saved logs to {logs_dir}/{site}-log.json')

    if not os.path.exists('links/'):
        os.makedirs('links/')
    with open(f'links/{site}-links.json', 'w') as f:
        json.dump(urls, f, indent=4)
        logger.info(f'Saved links to links/{site}-links.json')

def get_dictionaries():
    """
    Load the dictionaries from the files.
    """
    global urls, queue, visited_urls

    if os.path.exists(f'{LOGS}/{SITE}-log.json'):
        with open(f'{LOGS}/{SITE}-log.json', 'r') as f:
            logs = json.load(f)
            queue           = logs['queue']
            visited_urls    = logs['visited']
    if os.path.exists(f'links/{SITE}-links.json'):
        with open(f'links/{SITE}-links.json', 'r') as f:
            urls = json.load(f)

# XPath generation
def get_xpath(soup, tag):
    """
    Generates the XPath to the tag.
    """

    # Prioritize the tag's id
    _id = tag.get('id')
    if _id:
        if type(_id) == list:
            return f'//{tag.name}[@id="{" ".join(_id)}"]'
        else:
            return f'//{tag.name}[@id="{_id}"]'

    # Then the tag's class (only if unique throuout the page)
    _class = tag.get('class')
    if len(soup.find_all(tag.name, class_=_class)) == 1:
        if type(_class) == list:
            return f'//{tag.name}[@class="{" ".join(_class)}"]'
        else:
            return f'//{tag.name}[@class="{_class}"]'

    # Then the ids of the tag's children
    for child in tag.findChildren():
        _id = child.get('id')
        if _id:
            if type(_id) == list:
                return f'//{child.name}[@id="{" ".join(_id)}"]'
            else:
                return f'//{child.name}[@id="{_id}"]'

    # Then the classes of the tag's children (only if unique throuout the page)
    for child in tag.findChildren():
        _class = child.get('class')
        if _class:
            if len(soup.find_all(child.name, class_=_class)) == 1:
                if type(_class) == list:
                    return f'//{child.name}[@class="{" ".join(_class)}"]'
                else:
                    return f'//{child.name}[@class="{_class}"]'

    # If nothing worked, resort to the tag's text
    text = tag.text.strip().replace('\n', '')
    if text != '':
        return f'//{tag.name}/*[contains(text(), "{text}")]'
    return None

# =============================================================================
# =============================================================================
# ============================== GLOBAL VARIABLES =============================
# =============================================================================
# =============================================================================

class bcolors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKCYAN  = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'
    UNDERLINE = '\033[4m'

# Dictionaries where the key is the domain and the value is a list of URLs
queue = {}
visited_urls = {}

# Information dictionary
urls = {
    'site':     '',
    'homepage': '',
    'login':    {}, # Login pages URLs: {'idp': {...}}
    'idps':     []
}

# Session: python requests browser
session = requests.Session()

# Logger
logging.basicConfig()
logger = logging.getLogger('idps-identification')

# CONSTANTS
PROVIDERS = [
    'google', 'facebook', 'twitter', 'linkedin', 'github',
    'slack', 'microsoft', 'vk', 'vkontakte', 'apple',
    'amazon', 'kakao', 'yahoo', 'naver',
    'line', 'mailru', 'nintendo', 'paypal', 'reddit',
    'bitbucket', 'stackoverflow', 'instagram', 'odnoklassniki',
    'twitch', 'yandex', 'steam', 'pinterest', 'rambler',
    'weibo', 'sina', 'envato', 'soundcloud', 'tumblr',
    'dropbox', 'spotify', 'stackexchange', 'alipay',
    'aliexpress', 'clever', 'docomo', 'ok']

OAUTH_KEYWORDS = [
    'auth', 'login', 'account', 'signin',
    'signon', 'register', 'continue',
    'authentication', 'dialog'
]

DEBUG = True
SITE  = ''
MAX   = 10

USER_AGENT = f'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0'

# Regex to avoid requesting URLs that might cause a logout
LOGOUT_DENYLIST_REGEX = re.compile(
    '(sign|log|opt)[+-_]*(out|off)|leave',
    re.IGNORECASE
)

DENYLISTED_PATTERNS = [
    '/hc/',
    'https://support.', 'http://support.',
    'https://help.', 'http://help.',
    
]

DENYLISTED_DOMAINS = [
    'doubleclick.net', 'googleadservices.com',
    'google-analytics.com', 'googletagmanager.com',
    'googletagservices.com', 'googleapis.com',
    'googlesyndication.com', 'analytics.ticktok.com',
    'gstatic.com'
]

# =============================================================================
# =============================================================================
# =================================== MAIN ====================================
# =============================================================================
# =============================================================================

if __name__ == '__main__':
    # Arguments parsing
    parser = argparse.ArgumentParser(
        prog='idps-identification.py',
        description='Find supported IdPs in a website\'s login page'
    )

    parser.add_argument('-t', '--target',      required=False,    help='Target website')
    parser.add_argument('-S', '--stats',       default='stats',   help='Statistics folder')
    parser.add_argument('-R', '--reports',     default='reports', help='Reports folder')
    parser.add_argument('-l', '--logs',        default='logs',    help='Logs folder')
    parser.add_argument('-L', '--links',                          help='File containing the login links')
    parser.add_argument('-m', '--max',         default=MAX,       help=f'Maximum number of URLs to crawl (Default: {MAX})')
    parser.add_argument('-N', '--no-headless',                    help='Do not use a headless browser', action='store_true')
    parser.add_argument('-r', '--retest',                         help='Retest the URLs', action='store_true')
    parser.add_argument('-d', '--debug',                          help='Enable debug mode', action='store_true')

    args = parser.parse_args()

    logger.setLevel(logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    SITE    = (
        args.target
        .strip()
        .lower()
        .replace('http://',  '')
        .replace('https://', '')
    )
    LOGS        = args.logs
    STATS       = args.stats
    REPORTS     = args.reports
    MAX         = int(args.max)
    HEADLESS    = not args.no_headless

    # Create the folders if they do not exist
    if not os.path.exists(LOGS):
        os.makedirs(LOGS)
    if not os.path.exists(STATS):
        os.makedirs(STATS)
    if not os.path.exists(REPORTS):
        os.makedirs(REPORTS)
    if not os.path.exists('html'):
        os.makedirs('html')

    urls['site'] = SITE

    try:
        # Get dictionaries from the files
        if not args.retest:
            get_dictionaries()

        # Set the options for the browser
        browser = None

        options = webdriver.ChromeOptions()
        options.add_argument(f'user-agent={USER_AGENT}')

        options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})

        if HEADLESS:
            options.add_argument('headless')
            options.add_argument("--disable-gpu")

        # Check if the site is already crawled
        if urls['homepage'] == '':
            logger.info(f'Crawling the site to collect the URLs to test')

            # Visit the homepage and follow redirects
            if urls['homepage'] == '':
                logger.info('Searching for the homepage')

                response = session.get(f'https://{SITE}/', timeout=30)
                url = response.url
                add_to_visited(url)

                homepage = url
                urls['homepage'] = homepage
                logger.info(f'found: {homepage}')
            elif urls['homepage'] != '':
                homepage = urls['homepage']

        if len(urls['login']) == 0:
            # Note: remove this to search for more login pages when re-running the script
            logger.info('Searching for the login page')
            if browser is None:
                browser = webdriver.Chrome(options=options)

            # Clean the queue and visited_urls dictionaries
            queue = {}
            visited_urls = {}

            browser.get(urls['homepage'])
            time.sleep(1)

            # with open(f'html/{SITE}-homepage.html', 'w') as f:
            #     f.write(browser.page_source)

            # Get links from the homepage
            links = get_links(browser.current_url, browser.page_source, only_internal=True)

            login_url = get_login_url(links)
            if any(provider in login_url for provider in PROVIDERS):
                login_url = remove_query_string(login_url)
            if login_url != '':
                if not any(get_template_url(login_url) == get_template_url(_url) for _url in urls['login']):
                    urls['login'][login_url] = {}
                logger.info(f'found (1): {login_url}')

            for _url in links:
                add_to_queue(_url)

            # Check if contains login functionalities
            if is_login_page(browser.current_url, browser.page_source):
                if not any(get_template_url(login_url) == get_template_url(_url) for _url in urls['login']):
                    urls['login'][browser.current_url] = {}
                logger.info(f'found (2): {browser.current_url}')

            # Crawl the site to find *login page*
            while should_continue() and len(urls['login']) == 0:
                url = get_url_from_queue()

                if LOGOUT_DENYLIST_REGEX.search(url):
                    continue

                browser.get(url)
                add_to_visited(url)

                # Get links from the page
                links = get_links(browser.current_url, browser.page_source, only_internal=True)

                # TODO: here we should follow the redirects!
                login_url = get_login_url(links)
                if login_url != '':
                    if not any(get_template_url(login_url) == get_template_url(_url) for _url in urls['login']):
                        urls['login'][login_url] = {}
                    logger.info(f'found (3): {login_url}')

                for _url in links:
                    add_to_queue(_url)

                # Check if it's the login page
                if is_login_page(browser.current_url, browser.page_source):
                    if not any(get_template_url(login_url) == get_template_url(_url) for _url in urls['login']):
                        urls['login'][url] = {}
                    logger.info(f'found (4): {url}')
                    break
        if len(urls['login']) == 0:
            logger.info('login page not found!')
        # Visit the login page to search for the IdPs
        elif len(urls['idps']) == 0:
            # Note: remove this to search for more IdPs when re-running the script
            logger.info(f'Searching for IDPs OAuth links in {len(urls["login"])} pages')
            if browser is None:
                browser = webdriver.Chrome(options=options)

            '''
            1. Cycle through the login pages
            2. If the page is already dumped in memory: read from memory
            3. If the page is not in memory: get it from the web and dump it in memory
            4. Get IDPs from the page and add them to the urls['idps'] list if not already present (refer the login page URL in the IDP)
            '''
            for login_url in urls['login']:
                if os.path.exists(f'html/{SITE}{url_to_filename(login_url)}.html'):
                    logger.info('page retrieved from file')
                    with open(f'html/{SITE}{url_to_filename(login_url)}.html', 'r') as f:
                        html = f.read()
                else:
                    logger.info('page retrieved from the web')
                    browser.get(login_url)
                    time.sleep(1.5)
                
                    html = browser.page_source
                    with open(f'html/{SITE}{url_to_filename(login_url)}.html', 'w') as f:
                        f.write(html)

                links = get_links(login_url, html, only_internal=False) # !Get also external links
                for provider in PROVIDERS:
                    # First get the login tag and xpath for the provider
                    tag, xpath = get_oauth_tag(html, provider)
                    if tag is not None:
                        if provider not in urls['login'][login_url]:
                            urls['login'][login_url][provider] = {}
                        urls['login'][login_url][provider]['tag'] = tag
                        if not provider in urls['idps']:
                            urls['idps'].append(provider)
                        logger.info(f'found {bcolors.OKGREEN}{provider}{bcolors.ENDC} tag')
                    if xpath is not None:
                        if provider not in urls['login'][login_url]:
                            urls['login'][login_url][provider] = {}
                        urls['login'][login_url][provider]['xpath'] = xpath
                        if not provider in urls['idps']:
                            urls['idps'].append(provider)
                        logger.info(f'found {bcolors.OKGREEN}{provider}{bcolors.ENDC} xpath')

                    # Then search if there is also a direct OAuth link for this provider
                    provider_oauth_link = get_oauth_link(links, provider=provider)
                    if provider_oauth_link != '':
                        if provider not in urls['login'][login_url]:
                            urls['login'][login_url][provider] = {}
                        urls['login'][login_url][provider]['url'] = provider_oauth_link
                        if not provider in urls['idps']:
                            urls['idps'].append(provider)
                        logger.info(f'found {bcolors.OKGREEN}{provider}{bcolors.ENDC}: {provider_oauth_link}')
                    else:
                        # Try with source code links
                        links = get_source_code_links(browser.current_url, browser.page_source)
                        provider_oauth_link = get_oauth_link(links, provider=provider)
                        if provider_oauth_link != '':
                            if provider not in urls['login'][login_url]:
                                urls['login'][login_url][provider] = {}
                            urls['login'][login_url][provider]['url'] = provider_oauth_link
                            if not provider in urls['idps']:
                                urls['idps'].append(provider)
                            logger.info(f'found {bcolors.OKGREEN}{provider}{bcolors.ENDC}: {provider_oauth_link}')
        logger.info(f'Website crawled:\n{json.dumps(urls, indent=4)}')
    except SystemExit as e:
        sys.exit(e)
    except (SSLError, NewConnectionError, MaxRetryError, ConnectionError, ReadTimeoutError, ReadTimeout):
        logger.error(f'{SITE} timed out')
    except KeyboardInterrupt:
        logger.debug('KeyboardInterrupt received, exiting...')
        sys.exit(1)
    except:
        logger.error(traceback.format_exc())
        sys.exit(1)
    finally:
        save_dictionaries(SITE, LOGS)
        if browser is not None:
            browser.quit()
        logger.info(f'All done!')
        sys.exit(0)
