Tool for removing internal CA results from Nessus "SSL Certificate Cannot Be Trusted" plugin where a scan has already been completed.

Paste in the Issuer lines in the trusted issuer file:
e.g.
```
O=Nessus Users United/OU=Nessus Certification Authority (7b895e86)/L=New York/C=US/ST=NY/CN=Nessus Certification Authority (7b895e86)
```
And then pass this with "-t" parameter.

And whenever any of the items in the text file come up in results for this plugin, it will be removed from the output file.

Wish list:
- Multiple input files at once.
- Fully grepable results so that all untrused issuers can be easily edited and entered into trused issuer file.
- Checking the signature of results as the current version only validates the issuer line meaning there could be an untrusted result that isn't properly signed and this would be removed by this tool.
