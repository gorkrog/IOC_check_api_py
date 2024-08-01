import requests
import json
import datetime


def vt_add_ip_header(api_check: bool) -> str:
    if api_check:
        return f'vt_ip_address;last_https_certificate_date;network;last_modification_date;as_owner;asn;last_analysis_stats_malicious;last_analysis_stats_suspicious;last_analysis_stats_undetected;last_analysis_stats_harmless;last_analysis_stats_timeout;total_votes_harmless;total_votes_malicious;reputation;last_analysis_date;vt_link;'
    else:
        return f''


def vt_check_ip(ip_address: str, vt_aip: str) -> list:
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {
        "accept": "application/json",
        "x-apikey": f"{vt_aip}"
    }
    response = requests.request(method='GET', url=url, headers=headers)
    if response.status_code == 200:
        decoded_response = json.loads(response.text)
        vt_data = [
            ip_address,
            decoded_response["data"]["attributes"]["last_https_certificate_date"],
            decoded_response["data"]["attributes"]["network"],
            decoded_response["data"]["attributes"]["last_modification_date"],
            decoded_response["data"]["attributes"]["as_owner"],
            decoded_response["data"]["attributes"]["asn"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["malicious"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["suspicious"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["undetected"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["harmless"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["timeout"],
            decoded_response["data"]["attributes"]["total_votes"]["harmless"],
            decoded_response["data"]["attributes"]["total_votes"]["malicious"],
            decoded_response["data"]["attributes"]["reputation"],
            decoded_response["data"]["attributes"]["last_analysis_date"],
            decoded_response["data"]["links"]["self"]
        ]
        for i, item in enumerate(vt_data):
            if item == int:
                if item > 100000000:
                    vt_data[i] = datetime.datetime.fromtimestamp(item)

        return vt_data
    else:
        vt_data = ['response status code', response.status_code]
        return vt_data

def vt_add_domain_header(api_check: bool) -> str:
    if api_check:
        return f'domain,id;last_dns_records_date;last_modification_date;reputation;whois;whois_date;last_https_certificate_date;malicious;suspicious;undetected;harmless;timeout;harmless;malicious;reputation;last_analysis_date;vt_link;'
    else:
        return f''


def vt_check_domain(domain: str, vt_aip: str) -> list:
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {
        "accept": "application/json",
        "x-apikey": f"{vt_aip}"
    }
    response = requests.request(method='GET', url=url, headers=headers)
    if response.status_code == 200:
        decoded_response = json.loads(response.text)
        vt_data = [
            domain,
            decoded_response["data"]["id"],
            decoded_response["data"]["attributes"]["last_dns_records_date"],
            decoded_response["data"]["attributes"]["last_modification_date"],
            decoded_response["data"]["attributes"]["reputation"],
            decoded_response["data"]["attributes"]["whois_date"],
            decoded_response["data"]["attributes"]["last_https_certificate_date"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["malicious"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["suspicious"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["undetected"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["harmless"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]['timeout'],
            decoded_response["data"]["attributes"]["total_votes"]["harmless"],
            decoded_response["data"]["attributes"]["total_votes"]["malicious"],
            decoded_response["data"]["attributes"]["reputation"],
            decoded_response["data"]["attributes"]["last_analysis_date"],
            decoded_response["data"]["links"]["self"]
        ]
        for i, item in enumerate(vt_data):
            if item == int:
                if item > 100000000:
                    vt_data[i] = datetime.datetime.fromtimestamp(item)

        return vt_data
    else:
        vt_data = ['response status code', response.status_code]
        return vt_data


def vt_add_hash_header(api_check: bool) -> str:
    if api_check:
        return f'file_hash;original name;description;md5;sha1;sha256;first_submission_date;last_submission_date;last_analysis_date;malicious;suspicious;undetected;harmless;timeout;failure;type-unsupported;vt_link;'
    else:
        return f''


def vt_check_hash(file_hash: str, vt_aip: str) -> list:
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {
        "accept": "application/json",
        "x-apikey": f"{vt_aip}"
    }
    response = requests.request(method='GET', url=url, headers=headers)
    if response.status_code == 200:
        decoded_response = json.loads(response.text)
        vt_data = [
            file_hash,
            decoded_response["data"]["attributes"]["signature_info"]["original name"],
            decoded_response["data"]["attributes"]["signature_info"]["description"],
            decoded_response["data"]["attributes"]["md5"],
            decoded_response["data"]["attributes"]["sha1"],
            decoded_response["data"]["attributes"]["sha256"],
            decoded_response["data"]["attributes"]["first_submission_date"],
            decoded_response["data"]["attributes"]["last_submission_date"],
            decoded_response["data"]["attributes"]["last_analysis_date"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["malicious"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["suspicious"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["undetected"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["harmless"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["timeout"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["failure"],
            decoded_response["data"]["attributes"]["last_analysis_stats"]["type-unsupported"],
            decoded_response["data"]["links"]["self"]
        ]
        for i, item in enumerate(vt_data):
            if item == int:
                if item > 100000000:
                    vt_data[i] = datetime.datetime.fromtimestamp(item)

        return vt_data
    else:
        vt_data = ['response status code', response.status_code]
        return vt_data
