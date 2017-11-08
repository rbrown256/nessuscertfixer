#!/bin/python
# Created by Rob Brown November 2017 - https://markitzeroday.com/ https://twitter.com/rb256
import argparse, xml.etree.ElementTree, re
from lxml import etree

parser = argparse.ArgumentParser(description="Remove Nessus results for SSL certificates that are trusted in the environment, but you didn\'t configure Nessus for this prior to the scan.")
parser.add_argument("-f --file", type=str, required=True,
                   help="input file (.nessus format)", dest="infile", metavar="InputNessusFile")
parser.add_argument("-o --outfile", type=str, required=True, dest="outfile", 
                   help="output file (it will be in nessus format)", metavar="OutputNessusFile")
parser.add_argument("-t --trusted", type=str, required=True, dest="trusted", 
                   help="file containing trusted issuers", metavar="TrustedIssuerFile")
args = parser.parse_args()

with open(args.trusted) as trusted_file:
    trusted_issuers = trusted_file.readlines()

trusted_issuers = [x.strip() for x in trusted_issuers]

input_nessus = etree.parse(args.infile)
input_nessus_root = input_nessus.getroot()

unknown_cert_authority_regex = re.compile("signed by an unknown\\ncertificate authority :[.\\s]*\\|-Subject.*?\\s\\|-Issuer  : (.*)")

for ssl_vulnerability in input_nessus_root.findall("./Report/ReportHost/ReportItem[@pluginID='51192']/plugin_output"):
    text = ssl_vulnerability.text

    match = unknown_cert_authority_regex.search(text)
    
    if not match is None:
        
        issuer = match.group(1)

        print "[.] --------------------------------------------------------"
        print "[.] Found untrusted certificate authority:"
        print "[.] " + issuer

        if issuer in trusted_issuers:
            print "[+] In trusted issuer filei, removing from output file."
            parent = ssl_vulnerability.getparent()

            parent_parent = parent.getparent()

            parent_parent.remove(parent)
        else:
            print "[-] Not trusted."
            print "[*] " + issuer

input_nessus.write(args.outfile)
