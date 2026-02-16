# Security Toolkit 

A Python-based cybersecurity toolkit that scans **URLs, IP addresses, and file hashes** using real-world threat intelligence services:

- VirusTotal (URL + Hash scanning)
- Shodan (IP intelligence)

This tool is designed for security students, beginners in ethical hacking, and blue team learners**.

---

## Features

- URL malware scanning (VirusTotal)
- File hash reputation check (MD5 / SHA1 / SHA256)
- IP intelligence lookup (Shodan)
- Input validation (URL, IP, Hash)
- Colorful terminal output
- Multi-module structured project
- Error handling & keyboard interrupt support

---

## Project Structure
security_toolkit/
│
├── main.py
├── url_scanner.py
├── ip_scanner.py
├── hash_scanner.py
├── util.py
│
├── url.txt
├── ip.txt
├── hash.txt
│
└── README.md

## Requiments

Install required libraries :
``bash
pip install requests colorama

## How to run 
python main.py 


## menu option
1. URL scan
2. IP scan
3. Hash scan
4. Scan all
 you can enter values manually or leave blank to use .txt file 


API keys required 

VirusTotal 
Get free api key 
https://www.virustotal.com/gui/my-apikey

Shodan 
Get free api key
https://account.shodan.io/

Error Handling 
The tool handles:
   Invlid Input 
   Network Error
   API limits
   Invalid API keys
   Keyboard Interrupt(ctrl+c)

Educational purpose
This project created for:
    cybersecurit learning 
    Threat intelligence understanding 
    Ethical hacking practice 

Author 
Ledet Tamiru 
Cybersecurity student 
python | Networking | Ethical Hacking   

