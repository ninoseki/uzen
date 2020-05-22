from ipwhois import IPWhois
from ipwhois.exceptions import BaseIpwhoisException

obj = IPWhois("1.1.1.1")
try:
    rdap_answer = obj.lookup_rdap(depth=1)
    print(rdap_answer)
except BaseIpwhoisException as ex:
    print(ex)
