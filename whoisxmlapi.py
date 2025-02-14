import requests
import argparse
import json


def reverse(options):
    url = "https://reverse-whois.whoisxmlapi.com/api/v2"

    data = {
        "apiKey": options.apikey,
        "searchType": "current",
        "mode": "purchase",
        "punycode": True,
        "basicSearchTerms": {
            "include": options.keywords,
            "exclude": [
            ]
        }
    }


    r = requests.post(url=url, json=data)
    j = json.loads(r.text)

    for d in j['domainsList']: 
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

    parser.add_argument('-k', '--keywords', default=[], action='append', required=False, help="words to search for")
    parser.add_argument('-o', '--outfile', default="", required=False, help="output filename, else stdout")
    parser.add_argument('--apikey', default="", required=True, help="whoisxml api key")

    options = parser.parse_args()

    if len(options.keywords) > 4:
        print("Limited to 4 or less keywords per search")
        exit()

    reverse(options)


if __name__ == '__main__':
    main()
