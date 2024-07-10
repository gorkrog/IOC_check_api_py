import datetime

import modules.abuse as abuse
import modules.check_and_sort as check_and_sort
import modules.vt as vt


abuse_api = f''
vt_api = f''

apis = check_and_sort.check_apis(abuse_api, vt_api)

ips, emails, domains, hashes = check_and_sort.ioc_sort()

if ips:
    ip_result_file = f'ip_result_{datetime.datetime.now()}.csv'
    with open(ip_result_file, 'w', encoding='UTF8') as file:
        file.write(f'{abuse.abuse_add_ip_header(apis["abuse_api"])}{vt.vt_add_ip_header(apis["vt_api"])}\n')

    with open(ip_result_file, 'a', encoding='utf8') as ip_result_save:
        for ip in ips:
            ip_result = []
            if apis["abuse_api"]:
                ip_result.extend(abuse.abuse_check_ip(ip, abuse_api))

            if apis["vt_api"]:
                ip_result.extend(vt.vt_check_ip(ip, vt_api))

            ip_result = ';'.join(str(item) for item in ip_result)
            ip_result_save.write(f'{ip_result}\n')

if emails:
    pass

if domains:
    domain_result_file = f'domain_result_{datetime.datetime.now()}.csv'
    with open(domain_result_file, 'w', encoding='UTF8') as file:
        file.write(f'{vt.vt_add_domain_header(apis["vt_api"])}\n')

    with open(domain_result_file, 'a', encoding='utf8') as domain_result_save:
        for domain in domains:
            domain_result = []
            if apis["vt_api"]:
                domain_result.extend(vt.vt_check_domain(domain, vt_api))

            domain_result = ';'.join(str(item) for item in domain_result)
            domain_result_save.write(f'{domain_result}\n')

if hashes:
    hash_result_file = f'hash_result_{datetime.datetime.now()}.csv'
    with open(hash_result_file, 'w', encoding='UTF8') as file:
        file.write(f'{vt.vt_add_hash_header(apis["vt_api"])}\n')

    with open(hash_result_file, 'a', encoding='utf8') as hash_result_save:
        for file_hash in hashes:
            hash_result = []
            if apis["vt_api"]:
                hash_result.extend(vt.vt_check_hash(file_hash, vt_api))

            hash_result = ';'.join(str(item) for item in hash_result)
            hash_result_save.write(f'{hash_result}\n')
