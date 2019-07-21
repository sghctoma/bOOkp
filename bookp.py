#!/usr/bin/env python3

import getpass
import json
import logging
import os
import re
import requests
import sys
import urllib.parse

from argparse import ArgumentParser
from pyvirtualdisplay import Display
from selenium import webdriver


user_agent = {'User-Agent': 'krumpli'}
logger = logging.getLogger(__name__)

def create_session(email, password, browser_visible=False, proxy=None):
    if not browser_visible:
        display = Display(visible=0)
        display.start()

    logger.info("Starting browser")
    options = webdriver.ChromeOptions()
    if proxy:
        options.add_argument('--proxy-server='+proxy)
    browser = webdriver.Chrome(chrome_options=options)

    logger.info("Loading www.amazon.com")
    browser.get('https://www.amazon.com')

    logger.info("Logging in")
    browser.find_element_by_css_selector("#nav-signin-tooltip > a.nav-action-button").click()
    browser.find_element_by_id("ap_email").clear()
    browser.find_element_by_id("ap_email").send_keys(email)

    browser.find_element_by_id("ap_password").clear()
    browser.find_element_by_id("ap_password").send_keys(password)
    browser.find_element_by_id("signInSubmit").click()

    logger.info("Getting CSRF token")
    browser.get('https://www.amazon.com/hz/mycd/myx#/home/content/booksAll')

    match = re.search('var csrfToken = "(.*)";', browser.page_source)
    if match:
        csrf_token = match.group(1)

    cookies = {}
    for cookie in browser.get_cookies():
        cookies[cookie['name']] = cookie['value']

    browser.quit()
    if not browser_visible:
        display.stop();

    return cookies, csrf_token

"""
NOTE: This function is not used currently, because the download URL can be
constructed without this additional request. This might change in the future,
so I'm keeping this here just in case.

def get_download_url(user_agent, cookies, csrf_token, asin, device_id):
    logger.info("Getting download URL for " + asin)
    data_json = {
        'param':{
            'DownloadViaUSB':{
                'contentName':asin,
                'encryptedDeviceAccountId':device_id, # device['deviceAccountId']
                'originType':'Purchase'
            }
        }
    }    

    r = requests.post('https://www.amazon.com/hz/mycd/ajax',
        data={'data':json.dumps(data_json), 'csrfToken':csrf_token},
        headers=user_agent, cookies=cookies)
    rr = json.loads(r.text)["DownloadViaUSB"]
    return rr["URL"] if rr["success"] else None
"""

def get_devices(user_agent, cookies, csrf_token):
    logger.info("Getting device list")
    data_json = {'param': {'GetDevices': {}}}
    
    r = requests.post('https://www.amazon.com/hz/mycd/ajax',
        data={'data':json.dumps(data_json), 'csrfToken':csrf_token},
        headers=user_agent, cookies=cookies)
    devices = json.loads(r.text)["GetDevices"]["devices"]

    return [device for device in devices if 'deviceSerialNumber' in device]

def get_asins(user_agent, cookies, csrf_token):
    logger.info("Getting e-book list")
    startIndex = 0
    batchSize = 100
    data_json = {
        'param':{
            'OwnershipData':{
                'sortOrder':'DESCENDING',
                'sortIndex':'DATE',
                'startIndex':startIndex,
                'batchSize':batchSize,
                'contentType':'Ebook',
                'itemStatus':['Active'],
                'originType':['Purchase'],
            }
        }
    }

    # NOTE: This loop could be replaced with only one request, since the
    # response tells us how many items are there ('numberOfItems'). I guess that
    # number will never be high enough to cause problems, but I want to be on
    # the safe side, hence the download in batches approach.
    asins = []
    while True:
        r = requests.post('https://www.amazon.com/hz/mycd/ajax',
            data={'data':json.dumps(data_json), 'csrfToken':csrf_token},
            headers=user_agent, cookies=cookies)
        rr = json.loads(r.text)
        asins += [book['asin'] for book in rr['OwnershipData']['items']]

        if rr['OwnershipData']['hasMoreItems']:
            startIndex += batchSize
            data_json['param']['OwnershipData']['startIndex'] = startIndex
        else:
            break

    return asins

def download_books(user_agent, cookies, device, asins, directory):
    logger.info("Downloading {} books".format(len(asins)))
    cdn_url = 'http://cde-g7g.amazon.com/FionaCDEServiceEngine/FSDownloadContent'
    cdn_params = 'type=EBOK&key={}&fsn={}&device_type={}'
    for asin in asins:
        try:
            params = cdn_params.format(asin, device['deviceSerialNumber'], device['deviceType'])
            r = requests.get(cdn_url, params=params, headers=user_agent, cookies=cookies, stream=True)
            name = re.findall("filename\*=UTF-8''(.+)", r.headers['Content-Disposition'])[0]
            name = urllib.parse.unquote(name)
            name = name.replace('/', '_')
            with open(os.path.join(directory, name), 'wb') as f:
                for chunk in r.iter_content(chunk_size=512):
                    f.write(chunk)
            logger.info('Downloaded ' + asin + ': ' + name)
        except Exception as e:
            logger.debug(e)
            logger.error('Failed to download ' + asin)

def main():
    parser = ArgumentParser(description="Amazon e-book downloader.")
    parser.add_argument("--verbose", help="show info messages", action="store_true")
    parser.add_argument("--showbrowser", help="display browser while creating session.", action="store_true")
    parser.add_argument("--email", help="Amazon account e-mail address", required=True)
    parser.add_argument("--password", help="Amazon account password", default=None)
    parser.add_argument("--outputdir", help="download directory (default: books)", default="books")
    parser.add_argument("--proxy", help="HTTP proxy server", default=None)
    parser.add_argument("--asin", help="list of ASINs to download", nargs='*')
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)
    formatter = logging.Formatter('[%(levelname)s]\t%(asctime)s %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    password = args.password
    if not password:
        password = getpass.getpass("Your Amazon password: ")

    if os.path.isfile(args.outputdir):
        logger.error("Output directory is a file!")
        return -1
    elif not os.path.isdir(args.outputdir):
        os.mkdir(args.outputdir)

    cookies, csrf_token = create_session(args.email, password,
        browser_visible=args.showbrowser, proxy=args.proxy)
    if not args.asin:
        asins = get_asins(user_agent, cookies, csrf_token)
    else:
        asins = args.asin

    devices = get_devices(user_agent, cookies, csrf_token)
    print("Please choose which device you want to download your e-books to!")
    for i in range(len(devices)):
        print(" " + str(i) + ". " + devices[i]['deviceAccountName'])
    while True:
        try:
            choice = int(input("Device #: "))
        except:
            logger.error("Not a number!")
        if choice in range(len(devices)):
            break

    download_books(user_agent, cookies, devices[choice], asins, args.outputdir)

    print("\n\nAll done!\nNow you can use apprenticeharper's DeDRM tools " \
            "(https://github.com/apprenticeharper/DeDRM_tools)\n" \
            "with the following serial number to remove DRM: " +
            devices[choice]['deviceSerialNumber'])

if __name__ == '__main__':
    try:
    	sys.exit(main())
    except KeyboardInterrupt:
        logger.info("Exiting...")
