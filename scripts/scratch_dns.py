import socket
import requests

def crt_sh_subdomains(domain: str) -> list:
    try:
        resp = requests.get(f"https://crt.sh/?q=%25{domain}&output=json", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                if name and "*" not in name:
                    for sub in name.split("\n"):
                        subdomains.add(sub.strip())
            return sorted(list(subdomains))
    except:
        pass
    return []

def free_passive_dns(domain: str) -> list:
    subdomains = crt_sh_subdomains(domain)
    # limit to 50 to avoid taking too long
    subdomains = subdomains[:50]
    records = []
    for sub in subdomains:
        try:
            ip = socket.gethostbyname(sub)
            records.append([sub, ip])
        except socket.gaierror:
            pass
    return records

if __name__ == "__main__":
    print(free_passive_dns("google.com"))
