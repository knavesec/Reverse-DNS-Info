# Simple script to enumerate company domains via reverse WHOIS searching

## Description

Querying for reverse DNS info is a great way to enumerate domains for a target company. These scripts automate the process of discovering these domains, and outputting information for analysis.

Analyzing the WHOIS data for emails, names, addresses, states, zipcodes, etc is helpful for both gathering data and correlating domains. This script provides easy access to the information, with outputs in greppable format.


### Scripts

#### ViewDNS.info

The `dnsinfo.py` script will query [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) based on supplied keywords. This can be done without an API key, but only the top 500 domains will be returned, so try to use targeted keywords if you're limited. 

#### WhoisXML API

The `whoisxmlapi.py` script will query [https://www.whoisxmlapi.com/](https://www.whoisxmlapi.com/) based on up to four supplied search terms. This requires a subscription and API key to function. 

#### Mass lookups

With the compiled list of domains from the first two scripts (remember to `sort -u`), the `mass_whois.py` script will perform Whois lookups for each domain and output to a file for further manual analysis. 


## Usage

```
python3 dnsinfo.py -k "company keywords" -o outputfile.log
```

```
python3 dnsinfo.py -k "company keywords"

domain1.com
domain2.com
```

```
python3 whoisxmlapi.py --apikey "<token>" -k "keyword1" -k "keyword2"

domain1.com
domain2.com
```

```
python3 mass_whois.py -f domains_list.txt

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
python3 mass_whois.py -f domains_list.txt -g 

domain1.com : whois_emails : abuse@godaddy.com
domain1.com : whois_name : Target Company
domain1.com : whois_org : Target Company
domain1.com : whois_address : Address
domain1.com : whois_city : None
domain1.com : whois_state : None
domain1.com : whois_zipcode : None
domain1.com : whois_country : None
```