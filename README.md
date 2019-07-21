# bOOkp

Quick'n'dirty script to download all you Kindle ebooks.

I needed to backup all my Kindle e-books, so put together this script. It does
work for now, but a change in the download process will probably break it, and I
may not have the time to fix it right away.

You can download all your e-books (that are eligible for download), or you can
specify multiple ASINs to download. By default the script will only display
warnings, errors, and a finish message. If you want to see progress, you have to
use the `--verbose` flag. Selenium with ChromeDriver is used to handle login,
and you can display the browser with `--showbrowser` - this may come handy if
something goes wrong.

The only mandatory command line parameter is the e-mail address associated with
your Amazon account, but of course the script will need your password too - it
will ask for it if not given as parameter. Keep in mind that passwords given as
parameters will probably be stored in you history!

The script will also ask which of your devices you want to download your books
to. This is important, because the downloaded books will be DRMd to that
particular device. The serial number (which is required to remove DRM) will be
printed when the books are downloaded.

## Usage

```
usage: bookp.py [-h] [--verbose] [--showbrowser] --email EMAIL
                [--password PASSWORD] [--outputdir OUTPUTDIR] [--proxy PROXY]
                [--asin [ASIN [ASIN ...]]]

Amazon e-book downloader.

optional arguments:
  -h, --help            show this help message and exit
  --verbose             show info messages
  --showbrowser         display browser while creating session.
  --email EMAIL         Amazon account e-mail address
  --password PASSWORD   Amazon account password
  --outputdir OUTPUTDIR
                        download directory (default: books)
  --proxy PROXY         HTTP proxy server
  --asin [ASIN [ASIN ...]]
                        list of ASINs to download
```

## Requirements

* [Python 3.x](https://www.python.org)
* [ChromeDriver](https://sites.google.com/a/chromium.org/chromedriver/downloads)
* the following Python modules:
  * [requests](https://pypi.org/project/requests/)
  * [PyVirtualDisplay](https://pypi.org/project/PyVirtualDisplay/)
  * [selenium](https://pypi.org/project/selenium/)
