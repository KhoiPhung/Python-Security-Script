import requests
import threading
from queue import Queue
from colorama import init, Fore, Style
init(autoreset=True)
import sys


#Get user input
base_url = input("Enter URL: ").rstrip("/")
wordlist_path = input("Enter wordlist path (default: common.txt): ") or "/usr/share/wordlists/dirb/common.txt"
num_threads = int(input("Enter thread (int): ") or 64)

# Thread-safe queue
q = Queue()


def worker():
    while not q.empty():
        endpoint = q.get()
        url = f"{base_url}/{endpoint}"
        try:
            response = requests.get(url, timeout=3, allow_redirects=False) #Don't follow redirects 
            if response.status_code < 400:
                colored_status_code = Fore.YELLOW + str(response.status_code) + Style.RESET_ALL
                colored_url = Fore.CYAN + url + Style.RESET_ALL

                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('Location', 'No Location header')
                    print(f"[+] Found: {colored_url} (Status: {colored_status_code} -> Redirect to: {Fore.MAGENTA}{location}{Style.RESET_ALL})")
                else:
                    print(f"[+] Found: {colored_url} (Status: {colored_status_code})")

        except requests.RequestException:
            pass
        q.task_done()


# check if URL up cause program didn't exit when link was down
def check_url_up(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code >= 400:
            print(f"{Fore.RED}[-] Warning: Base URL responded with status code {response.status_code}")
        else:
            print(f"{Fore.GREEN}[+] Base URL is up! (Status: {response.status_code})")
        return True
    
    except requests.RequestException as e:
        print(f"{Fore.RED}[-] Failed to reach {url}: {e}")
        return False


def main():
    if not check_url_up(base_url):
        print("[-] Exiting since base URL is unreachable.")
        sys.exit()

    try:
        with open(wordlist_path, "r") as f:
            for line in f:
                word = line.strip()
                if word: 
                    q.put(word)
    except FileNotFoundError:
        print("[-] Wordlist file not found.")
        return
    
    # Start threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()

if __name__ == "__main__":
    main()
