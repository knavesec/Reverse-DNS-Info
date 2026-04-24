import argparse
import sys
import random
import time
import requests 
from bs4 import BeautifulSoup as bs


def _pretty_whois_text(text: str) -> str:
    """
    viewdns sometimes returns WHOIS blocks with line breaks collapsed.
    Re-insert newlines for common WHOIS field labels.
    """
    labels = [
        "Domain Name:",
        "Registry Domain ID:",
        "Registrar WHOIS Server:",
        "Registrar URL:",
        "Updated Date:",
        "Creation Date:",
        "Registry Expiry Date:",
        "Registrar Registration Expiration Date:",
        "Registrar:",
        "Registrar IANA ID:",
        "Registrar Abuse Contact Email:",
        "Registrar Abuse Contact Phone:",
        "Domain Status:",
        "Registry Registrant ID:",
        "Registrant Name:",
        "Registrant Organization:",
        "Registrant Street:",
        "Registrant City:",
        "Registrant State/Province:",
        "Registrant Postal Code:",
        "Registrant Country:",
        "Registrant Phone:",
        "Registrant Phone Ext:",
        "Registrant Fax:",
        "Registrant Fax Ext:",
        "Registrant Email:",
        "Registry Admin ID:",
        "Admin Name:",
        "Admin Organization:",
        "Admin Street:",
        "Admin City:",
        "Admin State/Province:",
        "Admin Postal Code:",
        "Admin Country:",
        "Admin Phone:",
        "Admin Phone Ext:",
        "Admin Fax:",
        "Admin Fax Ext:",
        "Admin Email:",
        "Registry Tech ID:",
        "Tech Name:",
        "Tech Organization:",
        "Tech Street:",
        "Tech City:",
        "Tech State/Province:",
        "Tech Postal Code:",
        "Tech Country:",
        "Tech Phone:",
        "Tech Phone Ext:",
        "Tech Fax:",
        "Tech Fax Ext:",
        "Tech Email:",
        "Registry Billing ID:",
        "Billing Name:",
        "Billing Organization:",
        "Billing Street:",
        "Billing City:",
        "Billing State/Province:",
        "Billing Postal Code:",
        "Billing Country:",
        "Billing Phone:",
        "Billing Phone Ext:",
        "Billing Fax:",
        "Billing Fax Ext:",
        "Billing Email:",
        "Name Server:",
        "DNSSEC:",
        "Source:",
        # footer / non-property sections
        "URL of the ICANN WHOIS Data Problem Reporting System:",
        ">>> Last update of WHOIS database:",
    ]

    t = text.replace("\r\n", "\n").replace("\r", "\n")
    # If the blob is already line-oriented, don't over-process it.
    if t.count("\n") >= 5:
        return t.strip()

    # Insert newlines before known labels (except at the very start).
    for lab in labels:
        t = t.replace(lab, f"\n{lab}")
    return t.lstrip("\n").strip()


def _strip_non_property_footer(text: str) -> str:
    """
    Drop large disclaimer/footer sections that come after the key/value properties.
    """
    stop_prefixes = (
        "URL of the ICANN WHOIS Data Problem Reporting System:",
        ">>> Last update of WHOIS database:",
        "NOTICE:",
        "TERMS OF USE:",
        "The Registry database contains",
        "For more information on Whois status codes",
    )
    kept: List[str] = []
    for line in text.splitlines():
        if any(line.startswith(p) for p in stop_prefixes):
            break
        kept.append(line)
    return "\n".join(kept).rstrip()


def _line_with_none_if_missing_value(line: str) -> str:
    """
    If a WHOIS line has a key but no value (e.g. 'Updated Date:'), append 'None'.
    """
    s = line.rstrip()
    if ":" not in s:
        return s
    key, rest = s.split(":", 1)
    if key.strip() and rest.strip() == "":
        return f"{key.rstrip()}: None"
    return s


def _is_empty_value_line(line: str) -> bool:
    s = line.rstrip()
    if ":" not in s:
        return False
    key, rest = s.split(":", 1)
    return bool(key.strip()) and rest.strip() == ""


def _looks_unregistered(text: str) -> bool:
    """
    Heuristics for unregistered domains. Different registries/ports return
    slightly different strings; ViewDNS often includes one of these phrases.
    """
    t = " ".join(text.lower().split())
    needles = (
        "no match for",
        "not found",
        "no data found",
        "domain not found",
        "status: free",
        "available",
        "no entries found",
    )
    return any(n in t for n in needles)

def whois_lookup(domain: str) -> str:
    domain = domain.strip()
    site = f"https://viewdns.info/whois/?domain={domain}"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
    }

    time.sleep(5 + random.randint(1, 10))
    r = requests.get(site, headers=headers, timeout=30)
    r.raise_for_status()

    soup = bs(r.text, "html.parser")

    # viewdns currently renders the WHOIS output inside <pre class="... whitespace-pre-wrap">
    pre_blocks = soup.find_all(
        "pre",
        {
            "class": "mt-4 p-4 bg-gray-100 text-base text-gray-900 rounded-md dark:bg-gray-700 dark:text-gray-100 whitespace-pre-wrap"
        },
    )
    if pre_blocks:
        raw = "\n\n".join(p.get_text("\n", strip=False).strip() for p in pre_blocks).strip()
        return _strip_non_property_footer(_pretty_whois_text(raw))

    # Fallback: first <pre> on the page
    pre = soup.find("pre")
    if pre:
        return _strip_non_property_footer(_pretty_whois_text(pre.get_text("\n", strip=False).strip()))

    raise RuntimeError("No WHOIS <pre> block found in response")

    # for d in dat: 
    #     if options.outfile != "":
    #         output(options, d.strip())
    #     else:
    #         print(d.strip())
        

def output(options, outstr):

    if options.outfile == "":
        print(outstr)
    else:
        f = open(options.outfile,'a+')
        f.write(outstr)
        f.write('\n')
        f.close()



def lookup_domains(dat, options):
    for domain in dat:
        try:
            text = whois_lookup(domain)
            if _looks_unregistered(text):
                d = domain.strip()
                if options.greppable:
                    output(options, f"{d} : unregistered")
                    print(f"Complete: {d}", file=sys.stderr)
                else:
                    output(options, f"Domain {d} Unregistered!")
                    print(f"Complete: {d}")
                continue
            if options.strip_empty:
                text = "\n".join(line for line in text.splitlines() if not _is_empty_value_line(line)).strip()
            if options.greppable:
                for line in text.splitlines():
                    if not options.strip_empty:
                        line = _line_with_none_if_missing_value(line)
                    if line.strip():
                        output(options, f"{domain.strip()} : {line}")
            else:
                output(options, f"{domain.strip()}:\n{text}\n")
            # Keep greppable output clean (no extra status lines).
            if not options.greppable:
                print(f"Complete: {domain.strip()}")
            else:
                print(f"Complete: {domain.strip()}", file=sys.stderr)
        except Exception as e:
            output(options, f"Error with domain: {domain.strip()} : {e}")
            print(f"Error with domain: {domain.strip()} : {e}")
        # try:
        #     w = whois.whois(domain.strip())
        #     if not options.greppable:
        #         output(options, domain.strip() + ":")
        #     for val in w:
        #         try:
        #             if not options.greppable:
        #                 output(options, '\t{val}: {data}'.format(val=val, data=w[val]))
        #             else:
        #                 output(options, '{domain} : whois_{val} : {data}'.format(domain=domain.strip(),val=val,data=w[val]))
        #         except:
        #             pass
        #     print("Complete: {domain}".format(domain=domain.strip()))
        # except Exception as e:

        #     if "No match for" in str(e): 

        #         print("Error with domain (unregistered): {domain}".format(domain=domain.strip()))
        #         output(options,"Error with domain (unregistered): {domain}".format(domain=domain.strip()))

        #     else: 
        #         print("Error with domain: {domain}".format(domain=domain.strip()))
        #         output(options,"Error with domain: {domain}".format(domain=domain.strip()))
        #     pass


def main():

    parser = argparse.ArgumentParser(description="perform whois lookups for a list of domains")

    parser.add_argument('-g', '--greppable', default=False, required=False, action="store_true", help="output in greppable format")
    parser.add_argument('--strip-empty', default=False, required=False, action="store_true", help="if set, do not output lines with empty values")
    parser.add_argument('-o', '--outfile', default="", required=False, help="output filename, else stdout")
    parser.add_argument('-f', '--file', default="", required=False, help="input filename, for specific domain queries")
    parser.add_argument('-d', '--domain', default="", required=False, help="single domain to query")

    options = parser.parse_args()

    if options.domain:
        dat = [options.domain]
    elif options.file:
        dat = open(options.file, 'r').readlines()
    else:
        raise SystemExit("Must provide --domain or --file")

    lookup_domains(dat, options)


if __name__ == '__main__':
    main()
