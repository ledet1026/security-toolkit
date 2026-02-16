from url_scanner import scanner
from ip_scanner import scan_ip
from hash_scanner import hash
from util import is_valid_hash, is_valid_ip, is_valid_url

def main():
    try:

        print("Select what you want to  scan: ")
        print("1. URL(s) only")
        print("2. IP address(es) only")
        print("3. Hash(es) only")
        print("4. All(Url + IP + Hash)")

        while True:
            try:
                choice = int(input("Enter your choice (1/2/3/4): "))
                if choice not in[1,2,3,4]:
                    raise ValueError("Invalid input please enter 1, 2, 3 or 4")
                break
            except ValueError as v:
                print(v)

        vt_api_key=None
        shodan_api=None

        if choice in [1,3,4]:
            vt_api_key=input("Enter Your VirusTotal API key: ")
        if choice in [2,4]:
            shodan_api=input("Enter you shodan API key: ")
        
        if choice== 1 or choice ==4:
            target_url=input("Enter target URL separated by comma or leave blank to use url.txt file: ")
            if target_url.strip()!="":
                urls=target_url.split(",")
                for idx, u in enumerate(urls, start=1):
                    u=u.strip()
                    if not is_valid_url(u):
                        print(f"Invalid url {u} skipped...")
                        continue
                    print(f"\nURL {idx}: {u}")
                    scanner(u,vt_api_key)
                    print("-"*80)
            else:
                try:
                    with open("url.txt","r") as f:
                        urls=f.read().splitlines()
                    if len(urls)==0:
                        print("The file is empty")
                    else:
                        for idx, u in enumerate(urls, start=1):
                            u=u.strip()
                            print(f"\nURL {idx}: {u}")
                            scanner(u,vt_api_key)
                            print("-"*80)
                except FileNotFoundError:
                    print("File url.txt is not exist!")

        if choice==2 or choice==4:
            ip_address=input("Enter target IP Address separated by comma or leave blank to use ip.txt: ")
            if ip_address.strip()!="":
                ips=ip_address.split(",")
                for  i in (ips):
                    i=i.strip()
                    if not is_valid_ip(i):
                        print(f"Invalid Ip {i} skipped...")
                        continue
                    print(f"\nIP {idx}: {i}")
                    scan_ip(i,shodan_api)
                    print("-"*80)
            else:
                try:
                    with open("ip.txt","r") as f:
                        ips=f.read().splitlines()
                    if len(ips)==0:
                        print("The file is empty")
                    else:
                        for idx, i in enumerate(ips, start=1):
                            i=i.strip()
                            print(f"\nIP {idx}: {i}")
                            scan_ip(i,shodan_api)
                            print("-"*80)
                except FileNotFoundError:
                    print("File ip.txt is not exist!")            
        if choice ==3 or choice ==4:
            file_hash=input("Enter Hash Value separated by comma: ")
            if file_hash.strip()!="":
                hashes=file_hash.split(",")
                for idx, h in enumerate(hashes, start=1):
                    h=h.strip()
                    if not is_valid_hash(h):
                        print(f"Invalid Hash {h} skipped...")
                        continue
                    print(f"\nHash {idx}: {h}")
                    hash(h,vt_api_key)
                    print("-"*80)
            else:
                try:
                    with open("hash.txt","r") as f:
                        hashes=f.read().splitlines()
                    if len(hashes)==0:
                        print("The file is empty")
                    else:
                        for idx, h in enumerate(hashes, start=1):
                            h=h.strip()
                            print(f"\nHash {idx}: {h}")
                            hash(h,vt_api_key)
                            print("-"*80)
                except FileNotFoundError:
                    print("File hash.txt is not exist!")

    except KeyboardInterrupt:
        print("\nScan cancelled by user") 
    except Exception as e:
        print(f"Unexpected error: {e}")               
if __name__ == "__main__":
    main()