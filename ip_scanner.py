import requests
shodan_base_url="https://api.shodan.io/shodan/host/"
from colorama import init, Fore, Style
init(autoreset=True)
def scan_ip(ip, shodan_api_key):
  
    url=f"{shodan_base_url}{ip}?key={shodan_api_key}"
    try:
        response3=requests.get(url, timeout=10)
        response3.raise_for_status()
        try:
            data= response3.json()
        except ValueError:
            print(f"Error: Unable to parse JSON response for IP {ip}")
            return
        if response3.status_code ==401:
            print(f"Error: Invalid Shodan API key for IP {ip}")
            return
        print(Fore.BLUE + f"IP: {ip}")
        print(Fore.CYAN + "Organization:", data.get("org","Unknown"))
        print(Fore.CYAN + "ISP:", data.get("isp","Unknown"))
        print(Fore.CYAN + "Country:", data.get("country_name","Unknown"))
        print(Fore.MAGENTA + "Open ports:", data.get("ports",[]))
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error while scanning IP {ip}: {http_err}")
    except requests.exceptions.ConnectionError:
        print(f"Network connection error while scanning IP {ip}")
    except requests.exceptions.Timeout:
        print(f"Request timed out while scanning IP {ip}")
    except requests.exceptions.RequestException as req_err:
        print(f"General error occurred while scanning IP {ip}: {req_err}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user!")
        exit()