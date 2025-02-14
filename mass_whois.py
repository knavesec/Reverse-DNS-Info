import whois
import argparse


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

    parser = argparse.ArgumentParser(description="perform whois lookups for a list of domains")

    parser.add_argument('-g', '--greppable', default=False, required=False, action="store_true", help="output in greppable format")
    parser.add_argument('-o', '--outfile', default="", required=False, help="output filename, else stdout")
    parser.add_argument('-f', '--file', default="", required=True, help="input filename, for specific domain queries")

    options = parser.parse_args()

    dat = open(options.file, 'r').readlines()

    lookup_domains(dat, options)


if __name__ == '__main__':
    main()
