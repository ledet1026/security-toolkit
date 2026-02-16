import re
import ipaddress
from urllib.parse import urlparse

#Validate url 
def is_valid_url(url):
    url=url.strip()
    if not url:
       return False
    if not urlparse(url).scheme:
       url="http://" + url
    parsed= urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)
#validate ip 
def is_valid_ip(ip):
    try :
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

#validate hashes
def is_valid_hash(hash):
    hash=hash.strip()
    return len(hash) in [32,40, 64]
