import requests
import json


def abuse_add_ip_header(api_check: bool) -> str:
    if api_check:
        return f'ipAddress;isPublic;isWhitelisted;abuseConfidenceScore;countryCode;usageType;isp;domain;hostnames;isTor;totalReports;'
    else:
        return f''


def abuse_check_ip(ip_address: str, abuse_api: str) -> list:
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': f'{ip_address}',
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': f'{abuse_api}'
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    if response.status_code == 200:
        decoded_response = json.loads(response.text)
        abuse_data = [
            decoded_response["data"]["ipAddress"],
            decoded_response["data"]["isPublic"],
            decoded_response["data"]["isWhitelisted"],
            decoded_response["data"]["abuseConfidenceScore"],
            decoded_response["data"]["countryCode"],
            decoded_response["data"]["usageType"],
            decoded_response["data"]["isp"],
            decoded_response["data"]["domain"],
            decoded_response["data"]["hostnames"],
            decoded_response["data"]["isTor"],
            decoded_response["data"]["totalReports"]
        ]
        return abuse_data
    else:
        abuse_data = ['response status code', response.status_code]
        return abuse_data
