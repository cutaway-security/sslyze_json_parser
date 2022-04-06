#!/usr/bin/env python3
import sys
import json
import argparse

#########################
# References
#########################
# Testing for SSL-TLS (OWASP-CM-001) - https://www.owasp.org/index.php/Testing_for_SSL-TLS_(OWASP-CM-001)
# SSLScan - https://github.com/rbsec/sslscan
# SSLyze - https://github.com/nabla-c0d3/sslyze
# SSLyze Python API - 
# jq show-struct - https://raw.githubusercontent.com/ilyash/show-struct/master/show_struct.py
# Parsing JSON with jq - http://www.compciv.org/recipes/cli/jq-for-parsing-json/

#########################
# Parse Arguments
#########################
p_args = argparse.ArgumentParser(description='SSLyze JSON Parser')
p_args.add_argument(metavar='filename.json',dest='inf') 
p_args.add_argument('-t','--target_list',action="store_true",help='list targets that were scanned') 
p_args.add_argument('-c','--cert_check',action="store_true",help='list targets with weak certificates') 
p_args.add_argument('-v','--vuln_check',action="store_true",help='list targets with known SSL/TLS vulnerabilities') 
args = p_args.parse_args()

#########################
# Tool Variables
#########################
tab = '    '

#########################
# Get data from file
#########################

try:
    d = json.loads(open(args.inf,'r').read())
except:
    print("%s: error opening file %s"%(sys.argv[0],args.inf))
    sys.exit()

#########################
# List servers and ports in scan
#########################
if args.target_list:
    print("\n### Target List ###")
    for target in d['server_scan_results']:
        print('%s:%s'%(target['server_location']['hostname'],target['server_location']['port']))

#########################
# Processing Variables
#########################
cipher_list = [
    "ssl_2_0_cipher_suites",
    "ssl_3_0_cipher_suites",
    "tls_1_0_cipher_suites",
    "tls_1_1_cipher_suites",
    "tls_1_2_cipher_suites",
    "tls_1_3_cipher_suites"
]

min_cipher_index  = 4
min_cipher_bitcnt = 128

weak_cert_list = {}
vuln_list = {}

session_resumption = []
http_headers = []
tls_fallback_scsv = []
tls_early_data = []

vuln_test_list = [
    'tls_compression', 
    'tls_1_3_early_data'
    'tls_fallback_scsv', 
    'heartbleed', 
    'openssl_ccs_injection', 
    'session_renegotiation', 
    'session_resumption', 
    'robot',
    'http_headers'
]

vuln_test_list_names = {
    'tls_compression':'Compression Vulnerability - CRIME', 
    'tls_fallback_scsv':'Fallback Vulnerability - POODLE', 
    'tls_1_3_early_data': 'Early Data Vulnerability',
    'heartbleed':'Heartbleed Vulnerability - HEARTBLEED', 
    'openssl_ccs_injection':'CCS Injection Vulnerability', 
    'session_renegotiation':'TLS/SSL Renegotiation Vulnerability',
    'session_resumption':'Resumption Vulnerability',
    'robot':'Oracle Threat Vulnerability - ROBOT',
    'http_headers': 'Vulnerable HTTP Headers'
}

#########################
# Process JSON data
#########################
for target in d['server_scan_results']:
    try:
        if target['connectivity_status'] == 'ERROR':
            d['server_scan_results'].remove(target)
    except Exception as e:
        print(e)
for target in d['server_scan_results']:
    server_name = '%s:%s'%(target['server_location']['hostname'],target['server_location']['port'])
    if target['scan_result'] is None:
        continue

    #########################
    # Identify servers that accept weak certificate family and bit length
    #########################
    for cipher in cipher_list:
        if target['scan_result'][cipher]['result']:
            count = len(target['scan_result'][cipher]['result']['accepted_cipher_suites'])
            if count:                
                certs = target['scan_result'][cipher]['result']['accepted_cipher_suites']
                for cert in certs:
                    if (cert['cipher_suite']['key_size'] < min_cipher_bitcnt) or (cipher_list.index(cipher) < min_cipher_index):
                        weak_cert = '%s.%s.%sbits'%(cipher,cert['cipher_suite']['openssl_name'],cert['cipher_suite']['key_size'])
                        if weak_cert in weak_cert_list.keys():
                            weak_cert_list[weak_cert].append(server_name)
                        else:
                            weak_cert_list[weak_cert] = [server_name]

    #########################
    # Identify servers that accept known vulnerabilities
    #########################
    # TLS Compression
    if target['scan_result']['tls_compression']['result'] and target['scan_result']['tls_compression']['result']['supports_compression']:
        if 'tls_compression' in vuln_list.keys():
            vuln_list['tls_compression'].append(server_name)
        else:
            vuln_list['tls_compression'] = [server_name]
    # TLS Fallback
    if target['scan_result']['tls_fallback_scsv']['result']:
        tls_fallback_scsv.append(target['scan_result']['tls_fallback_scsv']['result'])
    # TLS Early Data
    if target['scan_result']['tls_1_3_early_data']['result']:
        tls_early_data.append(target['scan_result']['tls_1_3_early_data']['result'])
    # Heartbleed
    if target['scan_result']['heartbleed']['result'] and target['scan_result']['heartbleed']['result']['is_vulnerable_to_heartbleed']:
        if 'heartbleed' in vuln_list.keys():
            vuln_list['heartbleed'].append(server_name)
        else:
            vuln_list['heartbleed'] = [server_name]
    # CCS Injection
    if target['scan_result']['openssl_ccs_injection']['result'] and target['scan_result']['openssl_ccs_injection']['result']['is_vulnerable_to_ccs_injection']:
        if 'openssl_ccs_injection' in vuln_list.keys():
            vuln_list['openssl_ccs_injection'].append(server_name)
        else:
            vuln_list['openssl_ccs_injection'] = [server_name]
    # TLS/SSL Renegotiation
    if target['scan_result']['session_renegotiation']['result'] and target['scan_result']['session_renegotiation']['result']['is_vulnerable_to_client_renegotiation_dos']:
        if 'session_renegotiation' in vuln_list.keys():
            vuln_list['session_renegotiation'].append(server_name)
        else:
            vuln_list['session_renegotiation'] = [server_name]
    # Resumption
    if target['scan_result']['session_resumption']['result']:
        session_resumption.append(target['scan_result']['session_resumption']['result'])
    # Oracle Threat
    if target['scan_result']['robot']['result'] and target['scan_result']['robot']['result']['robot_result'] != 'NOT_VULNERABLE_NO_ORACLE':
        if 'robot' in vuln_list.keys():
            vuln_list['robot'].append(server_name)
        else:
            vuln_list['robot'] = [server_name]
    # HTTP Headers
    if target['scan_result']['http_headers']['result']:
        http_headers.append(target['scan_result']['http_headers']['result'])
# Print cert results
if args.cert_check:
    print("\n### Certificate Issue List ###")
    for e in weak_cert_list.keys():
        # Family.Cert.BitLength
        print("%s%s"%(tab*0,e))
        # List of vulnerable systems by IP:Port
        for host in weak_cert_list[e]:
            print("%s%s"%(tab*1,host))
        print()
# Print vuln results
if args.vuln_check:
    print("\n### Vulnerability Issue List ###")
    for e in vuln_list.keys():
        # Vuln Family
        print("%s%s"%(tab*0,vuln_test_list_names[e]))
        # List of vulnerable systems by IP:Port
        for host in vuln_list[e]:
            print("%s%s"%(tab*1,host))
        print()
    if len(session_resumption) > 0:
        print('Session Resumption (Full support not provided, please forward resulting data to github issue to be added')
        for result in session_resumption:
            print(result)
    if len(http_headers) > 0:
        print('HTTP Headers (Full support not provided, please forward resulting data to github issue to be added')
        for result in http_headers:
            print(result)
    if len(tls_fallback_scsv) > 0:
        print('TLS Fallback SCSV (Full support not provided, please forward resulting data to github issue to be added')
        for result in tls_fallback_scsv:
            print(result)
    if len(tls_early_data) > 0:
        print('TLS Early Data (Full support not provided, please forward resulting data to github issue to be added')
        for result in tls_early_data:
            print(result)