#!/usr/bin/env python3

from OpenSSL import crypto
import sys
import re
import json
import argparse


def generate_extension(domains):

    if type(domains) == str:
        domains = re.split(',',domains)

    sans = []
    for i in domains:
        sans.append('DNS: %s' % i)
    sans = ', '.join(sans)

    base_constraints = ([
        crypto.X509Extension(b"keyUsage", False, b"Digital Signature, Non Repudiation, Key Encipherment"),
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
    ])
    x509_extensions = base_constraints
    x509_extensions.append(crypto.X509Extension(b'subjectAltName', False, sans.encode('utf-8')))
    return x509_extensions


def generate_key(bits):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, bits)
    return key


def generate_csr(commonName=None,countryName=None,companyName=None,unitName=None,provinceName=None,cityName=None,domains=None):

    req = crypto.X509Req()
    subject = req.get_subject()

    # common name
    subject.CN = commonName.encode('utf-8')
    subject.countryName = countryName.encode('utf-8')
    subject.stateOrProvinceName = provinceName.encode('utf-8')
    subject.localityName = cityName.encode('utf-8')
    subject.organizationName = companyName.encode('utf-8')
    subject.organizationalUnitName = unitName.encode('utf-8')

    if domains:
        req.add_extensions(generate_extension(domains))

    key = generate_key(2048)

    req.set_pubkey(key)
    req.sign(key, 'SHA256')

    return ({
        "pubkey":crypto.dump_certificate_request(crypto.FILETYPE_PEM, req).decode('utf-8'),
        "prikey":crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')
    })

if __name__ == '__main__':


    parser = argparse.ArgumentParser(description="parser ssl certificate request")
    parser.add_argument('-d','--dns',required=False ,help="other domains, format: a.com,b.com,x.a.com,*.b.com", dest='dns', default=None)
    parser.add_argument('-cn',required=True, help='primary domain')
    parser.add_argument('-country_name',required=True,help='country code')
    parser.add_argument('-company_name',required=True,help='company name')
    parser.add_argument('-unit_name',required=True,help='unit name')
    parser.add_argument('-province_name', required=True, help='province name')
    parser.add_argument('-city_name', required=True, help='city name')

    args = parser.parse_args()

    csr = generate_csr(
        domains=args.dns,
        commonName=args.cn,
        countryName=args.country_name,
        companyName=args.company_name,
        unitName=args.unit_name,
        provinceName=args.province_name,
        cityName=args.city_name
    )

    print(json.dumps(csr))
    sys.exit(0)

