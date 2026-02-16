import requests
import time
from colorama import init, Fore, Style
init(autoreset=True)
def scanner(url_name,vt_api_key):
    """
       Scans a single URL using VirusTotal API and prints the results.
    """
    headers={
        "x-apikey":vt_api_key
    }
    url="https://www.virustotal.com/api/v3/urls"
    try:
        response=requests.post(url, headers=headers,data={"url":url_name}, timeout=10)

        if response.status_code ==401:
            print("Error: Invalid API key")
        elif response.status_code ==429:
            print("Error: API limit exceeded")
            return
        elif response.status_code != 200:
            print("Error:",response.status_code)
            return 

        result=response.json()

        analysis_id=result["data"]["id"]
        print("Analysis ID: ",analysis_id)
        analysis_url=f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        while True:
            response2=requests.get(analysis_url,headers=headers)
            result2=response2.json()
            status_field=result2["data"]["attributes"]["status"]
            if status_field == "completed":
                break
            print("Waiting for scan to complete...")
            time.sleep(5)
        stats=result2["data"]["attributes"]["stats"]
        print("Malicious: ",stats.get("malicious",0))
        print("Suspicious: ",stats.get("suspicious",0))
        print("Harmless: ",stats.get("harmless",0))
        print("Undetected: ",stats.get("undetected",0))
        auto_detect(stats)
    except requests.exceptions.ConnectionError:
        print(f"Network connection error while scanning Urls {url_name}")
    except requests.exceptions.Timeout:
        print(f"Request timed out while scanning urls {url_name}")
    except requests.exceptions.RequestException as req_err:
        print(f"General error occurred while scanning Urls {url_name}: {req_err}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user!")
        exit()
def auto_detect(check):
    """
    Determines the final result based on stats: Malicious, Suspicious, or Safe.
    """
    if check.get("malicious",0) >0:
        print(Fore.RED + "Final Result: Malicious")
    elif check.get("suspicious",0) >0:
        print(Fore.YELLOW + "Final Result: Suspicious")
    else:
        print(Fore.GREEN + "Final result: safe")