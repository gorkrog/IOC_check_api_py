import re


def check_apis(abuse_aip: str, vt_api: str) -> dict:
    api_dict = {}

    if not abuse_aip:
        api_dict.update({"abuse_api": False})
    else:
        api_dict.update({"abuse_api": True})

    if not vt_api:
        api_dict.update({"vt_api": False})
    else:
        api_dict.update({"vt_api": True})

    return api_dict


def ioc_sort():
    ips = []
    emails = []
    domains = []
    hashes = []

    with open('IOC', 'r', encoding="utf8") as file:
        for row in file:
            #to do: fix ip addres handling
            if re_res := re.search(r"\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9][0-9]|[0-9])\b", row):
                ips.append(re_res.group(0))
            elif re_res := re.search(r"\b[0-9a-zA-Z]*@[0-9a-zA-Z]*\.[0-9a-zA-Z]*.*\b", row):
                emails.append(re_res.group(0))
            elif re_res := re.search(r"\b[0-9a-zA-Z]{1,63}\.([a-z]{2,24}\.[a-z]{2,24}|[a-z]{2,24})\b", row):
                domains.append(re_res.group(0))
            elif re_res := re.search(r"\b([a-z0-9]{32}|[a-z0-9]{40}|[a-z0-9]{64})\b", row):
                hashes.append(re_res.group(0))
            else:
                pass

        return ips, emails, domains, hashes
