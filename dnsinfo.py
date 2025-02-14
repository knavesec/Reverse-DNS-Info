import requests
from bs4 import BeautifulSoup as bs
import argparse


def dnsinfo(options):

    dat = []

    entry = '+'.join(options.keywords.split(' '))

    site = "https://viewdns.info/reversewhois/?q={entry}&t=1".format(entry=entry)
    headers = {
        'User-Agent' : "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1"
    }

    r = requests.get(site,headers=headers)

    soup = bs(r.text, "html.parser")

    c = soup.find_all("td", {"class":"px-6 py-4 whitespace-nowrap text-base font-medium text-gray-900 dark:text-gray-100"})

    #tables = soup.find("table", border=1)
    try:
        for i in c:
            dat.append(i.text)
        # for tr in tables.find_all("tr"):
        #     dat.append( tr.find_all("td")[0].text )
    except AttributeError as e:
        print("No domains returned, exiting...")
        return

    for d in dat: 
        if options.outfile != "":
            output(options, d.strip())
        else:
            print(d.strip())
        

def output(options, outstr):

    if options.outfile == "":
        print(outstr)
    else:
        f = open(options.outfile,'a+')
        f.write(outstr)
        f.write('\n')
        f.close()


def main():

    parser = argparse.ArgumentParser(description="perform keyword based reverse whois searches via viewdns.info")

    parser.add_argument('-k', '--keywords', default="", required=False, help="words to search for")
    parser.add_argument('-o', '--outfile', default="", required=False, help="output filename, else stdout")

    options = parser.parse_args()

    dnsinfo(options)


if __name__ == '__main__':
    main()
