import requests


api_key = ""
url = "https://reverse-whois.whoisxmlapi.com/api/v2"

data = {
    "apiKey": api_key,
    "searchType": "current",
    "mode": "purchase",
    "punycode": True,
    "basicSearchTerms": {
        "include": [
            "walmart"
        ],
        "exclude": [
        ]
    }
}


r = requests.post(url=url, json=data)
print(r.text)