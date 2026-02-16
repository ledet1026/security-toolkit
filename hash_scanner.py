import requests
from colorama import init, Fore, Style
init(autoreset=True)

def hash(hash_value, api_key):

    headers={
    "x-apikey":api_key
}
    url =  f"https://www.virustotal.com/api/v3/files/{hash_value}"
    try:
        response= requests.get(url,headers=headers, timeout=10)

        if response.status_code ==401:
            print("Error: Invalid API key")
            return 
        elif response.status_code ==404:
            print("Error: Hash not found")
            return 
        
        elif response.status_code ==429:
            print("Error: API limit exceeded")
            return 
        elif response.status_code != 200:
            print("Error:",response.status_code)
            return 
        try:
            data=response.json()
        except:
            print("Error: Response is not JSON")
            exit()

        status=data["data"]["attributes"]
        vote=status.get("total_votes",{"harmless":0,"malicious":0})
        mal= vote.get("malicious",0)
        harm=vote.get("harmless",0) 
        susp=vote.get("suspicious",0) 
        undetect=vote.get("undetected",0)

        print("Malicious: ",mal)
        print("Suspicious: ",susp)
        print("Harmless: ",harm)
        print("Undetected: ",undetect)
        auto_detect(mal,susp)
    except requests.exceptions.ConnectionError:
        print(f"Network connection error while scanning Hashes {hash_value}")
    except requests.exceptions.Timeout:
        print(f"Request timed out while scanning Hashes {hash_value}")
    except requests.exceptions.RequestException as req_err:
        print(f"General error occurred while scanning Hashes {hash_value}: {req_err}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user!")
        exit()
def auto_detect(malicious, suspicious):
    """
    Decide final result from VirusTotal stats.
    """
    if malicious > 0:
        print(Fore.RED + "Final Result: Malicious")
    elif suspicious >0:
        print(Fore.YELLOW + "Final Result: Suspicious")
    else:
        print(Fore.GREEN + "Final Result: Safe ")

