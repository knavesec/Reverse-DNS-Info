# Simple script to enumerate company domains via reverse WHOIS searching

## Description

Querying [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) for reverse DNS info is a great way to enumerate domains for a target company. This script automates the process of discovering these domains, and outputting information for analysis.

Analyzing the WHOIS data for emails, names, addresses, states, zipcodes, etc is helpful for both gathering data and correlating domains. This script provides easy access to the information, with outputs in greppable format.

This will method can only grab the top 500 results due to the nature of the website. 

## Usage

```
python3 dnsinfo.py -k "company keywords" -o outputfile.log
```

```
python3 dnsinfo.py -k "company keywords"


domain1.com
    emails: abuse@godaddy.com
    name: Target Company
    org: Target Company
    address: Address
    city: None
    state: None
    zipcode: None
    country: None
```

```
python3 dnsinfo.py -k "company keywords" -g


domain1.com : whois_emails : abuse@godaddy.com
domain1.com : whois_name : Target Company
domain1.com : whois_org : Target Company
domain1.com : whois_address : Address
domain1.com : whois_city : None
domain1.com : whois_state : None
domain1.com : whois_zipcode : None
domain1.com : whois_country : None
```
