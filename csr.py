#!/usr/bin/env python3

from OpenSSL import crypto
import sys
import re
import json
import argparse
import ecdsa


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


def generate_key(key_type='RSA', bits=2048):
    if key_type.upper() not in ['RSA','ECDSA']:
        print(json.dumps({"code":"fail", "message":"key type error {} in (RSA,ECDSA)".format(key_type.upper())}))
        sys.exit(0)
    key_type = key_type.upper()

    key = None
    if key_type == 'RSA':
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, int(bits))
    elif key_type == 'ECDSA':
        key_sizes = [str(i) for i in [192,224,256,284,521]]
        if bits not in key_sizes:
            print(json.dumps({"code": "fail", "message": "key size error {} in ({})".format(bits,(", ".join(key_sizes)))}))
            sys.exit(0)
        sizes = ecdsa.curves
        if bits == '192':
            bits = sizes.NIST192p
        elif bits == '224':
            bits = sizes.NIST224p
        elif bits == '256':
            bits = sizes.NIST256p
        elif bits == '384':
            bits = sizes.NIST384p
        elif bits == '256':
            bits = sizes.NIST256p
        elif bits == '521':
            bits = sizes.NIST521p

        key = crypto.load_privatekey(crypto.FILETYPE_PEM, ecdsa.SigningKey.generate(curve=bits,hashfunc='sha256').to_pem())

    return key


def generate_csr(commonName=None,email='',countryName=None,companyName=None,unitName=None,provinceName=None,cityName=None,domains=None,key_type='rsa',key_size=2048,hash=None):

    req = crypto.X509Req()
    subject = req.get_subject()

    # common name
    subject.CN = commonName.encode()
    subject.countryName = countryName.encode()
    subject.stateOrProvinceName = provinceName.encode()
    subject.localityName = cityName.encode()
    subject.organizationName = companyName.encode()
    subject.organizationalUnitName = unitName.encode()
    subject.emailAddress = email.encode()

    if domains:
        req.add_extensions(generate_extension(domains))

    key = generate_key(key_type,bits=key_size)

    req.set_pubkey(key)
    req.sign(key, hash)

    return ({
        "pubkey":crypto.dump_certificate_request(crypto.FILETYPE_PEM, req).decode(),
        "prikey":crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode()
    })

if __name__ == '__main__':


    parser = argparse.ArgumentParser(description="parser ssl certificate request")
    parser.add_argument('-d','--dns',required=False ,help="other domains, format: a.com,b.com,x.a.com,*.b.com", dest='dns', default=None)
    parser.add_argument('-cn',required=True, help='primary domain')
    parser.add_argument('-email', required=True, help='email address')
    parser.add_argument('-country_name',required=True,help='country code')
    parser.add_argument('-company_name',required=True,help='company name')
    parser.add_argument('-unit_name',required=True,help='unit name')
    parser.add_argument('-province_name', required=True, help='province name')
    parser.add_argument('-city_name', required=True, help='city name')

    parser.add_argument('-key_type', required=False, help='key type rsa, ecdsa (default:rsa)', default='RSA')
    parser.add_argument('-key_size', required=False, help='key size: rsa:1024,2048,4096 ecdsa:192,224,256,284,521 (default:2048)', default=2048)

    parser.add_argument('-hash', required=False, help='hash function name : sha1, sha256, sha512 (default:sha256)', default='sha256')

    args = parser.parse_args()

    csr = generate_csr(
        domains=args.dns,
        commonName=args.cn,
        email=args.email,
        countryName=args.country_name,
        companyName=args.company_name,
        unitName=args.unit_name,
        provinceName=args.province_name,
        cityName=args.city_name,
        key_type=args.key_type,
        key_size=args.key_size,

        hash=args.hash
    )

    print(json.dumps(csr))
    sys.exit(0)

