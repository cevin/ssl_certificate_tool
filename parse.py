#!/usr/bin/env python3

from OpenSSL import crypto
import sys
import json
import argparse
from cryptography.hazmat.backends.openssl.backend import serialization




# str = """-----BEGIN CERTIFICATE REQUEST-----
# MIIC4jCCAcoCAQAwVDEOMAwGA1UEAwwFYS5jb20xCzAJBgNVBAYTAkNOMQswCQYD
# VQQIDAJFRTELMAkGA1UEBwwCYWExDzANBgNVBAoMBuWkp+WVijEKMAgGA1UECwwB
# ZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKfSVEPmZZMsZGFFIoXY
# fL5wI7sC/98S3Yips69rMBxsxqADj2xW/8SXM4cvVxarlJ52GY44SdWnkRCF9XP0
# 6A7nTWEdtahSOJqmz5HCOxHojZ2k/V2NNmLjsC+ZrQqRK60mLO1qb/yYpFzI+nJc
# 3r42+xLdzktbmEWCDeiwwCvi0QqWBDtQJ3zE+K4FcFCITLAYB0RFzNbX+NH4ZbWG
# PDzmVmZjOKA4hIJrbCFdbaUk+sdb5+N6D8TSJgfcgT/28wBQiCgheC27VSV+LBi5
# Nc3yUVoI3O1nwoT26nDFtN4U1M0wjPxYqpK3ycJZklNFlH+RT6VHF++a1yXMEtQ9
# SNsCAwEAAaBJMEcGCSqGSIb3DQEJDjE6MDgwCwYDVR0PBAQDAgXgMAkGA1UdEwQC
# MAAwHgYDVR0RBBcwFYIFYS5jb22CBWIuY29tggVjLmNvbTANBgkqhkiG9w0BAQsF
# AAOCAQEAa5BWHTSrYEQZB4GP7VptWR6zJN8S7AVQjdjkwXmrTWcG1lEAV0VWxOYh
# kIoE89wihDHjsVjoxHmvZlOV8D4vLEYv4csf/YVin/8sznY/kiyG6oggtvTkpAYx
# 1b//KfIlPOA/vFYNgsZnnYPpXaKzZFfHEML7w1/2ZFJN6DPC5/j662npqdvE06nM
# rNc3xfxm4S0vPGl4KEdR0NcRIttivlUXRvUVqTytFxSe15WmfMciopPahz2ZwreE
# FAcmSYzEBgTYvO/XjrfLRccC6m+OoEaPk84kKvo8lGZ1xCRI+Plj9f87FAnV5mHH
# zWntmgQfuruRNJe5P8rWevPqcEARxA==
# -----END CERTIFICATE REQUEST-----"""

# str = """-----BEGIN NEW CERTIFICATE REQUEST-----
# MIIDPzCCAqgCAQAwZDELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAmJqMQswCQYDVQQH
# EwJiajERMA8GA1UEChMIbXhjei5uZXQxETAPBgNVBAsTCG14Y3oubmV0MRUwEwYD
# VQQDEwx3d3cubXhjei5uZXQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMQ7
# an4v6pHRusBA0prMWXMWJCXY1AO1H0X8pvZj96T5GWg++JPCQE9guPgGwlD02U0B
# NDoEABeD1fwyKZ+JV5UFiOeSjO5sWrzIupdMI7hf34UaPNxHo6r4bLYEykw/Rnmb
# GKnNcD4QlPkypE+mLR4p0bnHZhe3lOlNtgd6NpXbAgMBAAGgggGZMBoGCisGAQQB
# gjcNAgMxDBYKNS4yLjM3OTAuMjB7BgorBgEEAYI3AgEOMW0wazAOBgNVHQ8BAf8E
# BAMCBPAwRAYJKoZIhvcNAQkPBDcwNTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcN
# AwQCAgCAMAcGBSsOAwIHMAoGCCqGSIb3DQMHMBMGA1UdJQQMMAoGCCsGAQUFBwMB
# MIH9BgorBgEEAYI3DQICMYHuMIHrAgEBHloATQBpAGMAcgBvAHMAbwBmAHQAIABS
# AFMAQQAgAFMAQwBoAGEAbgBuAGUAbAAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABp
# AGMAIABQAHIAbwB2AGkAZABlAHIDgYkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# AAAAAAAAAAAAAAAAAAAAADANBgkqhkiG9w0BAQUFAAOBgQBIKHVhHb9FZdVLV4VZ
# 9DK4aBSuYY//jlIpvsfMIdHXfAsuan7w7PH87asp1wdb6lD9snvLZix1UGK7VQg6
# wUFYNlMqJh1m7ITVvzhjdnx7EzCKkBXSxEom4mwbvSNvzqOKAWsDE0gvHQ9aCSby
# NFBQQMoW94LqrG/kuIQtjwVdZA==
# -----END NEW CERTIFICATE REQUEST-----"""

class BaseException(Exception):
    pass
class CertTypeErrorException(BaseException):
    pass

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="parser ssl certificate request")
    parser.add_argument('-c','--csr',required=True ,help="csr content", dest='csr')
    args = parser.parse_args()

    str = "\n".join(args.csr.split("\\n"))

    try:
        try:
            req = crypto.load_certificate_request(crypto.FILETYPE_PEM, str)
        except ValueError:
            raise CertTypeErrorException

        subject = req.get_subject()
        pubkey = req.get_pubkey()
        components = dict(subject.get_components())

        ret = {}

        for i in components:
            key = i
            value = components[i]
            ret[key if type(key) != bytes else key.decode()] = value if type(value) != bytes else value.decode()


        # parse
        exts = {}
        extensions = req.get_extensions()
        if extensions:
            for value in extensions:
                name = value.get_short_name()
                name = name if type(name) == str else name.decode()
                # todo: bug value.__str__() sometimes will be error
                if name == 'subjectAltName':
                    exts[name] = value.__str__()

        if 'subjectAltName' in exts:
            ret['dns'] = exts['subjectAltName']

        ## parse key type and bits
        ret['key_type'] = 'RSA' if pubkey.type() == crypto.TYPE_RSA else ('ECDSA' if pubkey.type() == 408 else 'DSA')
        ret['key_bits'] = pubkey.bits()
        ret['pubkey'] = pubkey.to_cryptography_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        print(json.dumps({"code":"success", "data":ret}))
    except CertTypeErrorException:
        print({"code":"fail","message":"cert parse error"})
        sys.exit(1)
    except Exception as e:
        print({"code":"fail","message":e.__str__()})
        sys.exit(1)