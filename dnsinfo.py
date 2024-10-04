import requests
from bs4 import BeautifulSoup as bs
import whois
import argparse


def dnsinfo(options):

    dat = []

    if options.file == "":
        entry = '+'.join(options.keywords.split(' '))

        site = "https://viewdns.info/reversewhois/?q={entry}".format(entry=entry)
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

        tables = soup.find("table", border=1)
        try:
            for tr in tables.find_all("tr"):
                dat.append( tr.find_all("td")[0].text )
        except AttributeError as e:
            print("No domains returned, exiting...")
            return

        dat = dat[1:len(dat)]


    else: 

        dat = open(options.file, 'r').readlines()

    lookup_domains(dat, options)


def lookup_domains(dat, options):
    # values = ["emails", "name", "org", "address", "city", "state", "zipcode", "country"]
    for domain in dat:
        try:
            w = whois.whois(domain.strip())
            if not options.greppable:
                output(options, domain.strip() + ":")
            for val in w:
                try:
                    if not options.greppable:
                        output(options, '\t{val}: {data}'.format(val=val, data=w[val]))
                    else:
                        output(options, '{domain} : whois_{val} : {data}'.format(domain=domain.strip(),val=val,data=w[val]))
                except:
                    pass
            print("Complete: {domain}".format(domain=domain.strip()))
        except Exception as e:

            if "No match for" in str(e): 

                print("Error with domain (unregistered): {domain}".format(domain=domain.strip()))
                output(options,"Error with domain (unregistered): {domain}".format(domain=domain.strip()))

            else: 
                print("Error with domain: {domain}".format(domain=domain.strip()))
                output(options,"Error with domain: {domain}".format(domain=domain.strip()))
            pass


def output(options, outstr):

    if options.outfile == "":
        print(outstr)
    else:
        f = open(options.outfile,'a+')
        f.write(outstr)
        f.write('\n')
        f.close()


def main():

    parser = argparse.ArgumentParser(description="yeet, todo")

    parser.add_argument('-k', '--keywords', default="", required=False, help="words to search for")
    parser.add_argument('-g', '--greppable', default=False, required=False, action="store_true", help="output in greppable format")
    parser.add_argument('-o', '--outfile', default="", required=False, help="output filename, else stdout")
    parser.add_argument('-f', '--file', default="", required=False, help="input filename, for specific domain queries")

    options = parser.parse_args()

    dnsinfo(options)


if __name__ == '__main__':
    main()
