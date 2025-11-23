import requests
import time
import argparse
import os
import re
import threading
from collections import deque
from itertools import cycle
from urllib.parse import urlparse

def print_logo():
    CYAN = "\033[96m"
    PURPLE = "\033[95m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

    logo = [
        r" __       _________  ____                     ",
        r" \ \     / /__   __| |  _ \ ___  ___ ___  _ __  ",
        r"  \ \   / /   | |    | |_) / _ \/ __/ _ \| '_ \ ",
        r"   \ \/ /     | |    |  _ <  __/ (_| (_) | | | |",
        r"    \__/      |_|    |_| \_\___|\___\___/|_| |_|"
    ]

    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n")

    for line in logo:
        time.sleep(0.05)
        print(f"{BOLD}{CYAN}{line[:23]}{PURPLE}{line[23:]}{RESET}")

    print("\n")
    print(f"{CYAN}    [+]{RESET} Tool    : {BOLD}VT Domain Reconnisiance{RESET}")
    print(f"{CYAN}    [+]{RESET} Version : {BOLD}1.1{RESET}")
    print(f"{CYAN}    [+]{RESET} Dev     : {BOLD}Luxiel{RESET}")
    print(f"{CYAN}    [+]{RESET} Github  : {BOLD}https://github.com/0xLuxieL/VT-Recon{RESET}")
    print(f"\n{PURPLE}    ============================================={RESET}\n")


class Config:
    API_URL = "https://www.virustotal.com/vtapi/v2/domain/report"
    COOLDOWN = 65
    TIMEOUT = 10
    MAX_RETRIES = 3

    COLORS = {
        'cyan': '\033[96m', 'magenta': '\033[95m', 'green': '\033[92m',
        'yellow': '\033[93m', 'blue': '\033[94m', 'red': '\033[91m',
        'reset': '\033[0m', 'grey': '\033[90m'
    }

    @classmethod
    def get_api_keys(cls):
        keys_env = os.getenv('VT_API_KEYS')
        if not keys_env:
            raise ValueError("VT_API_KEYS environment variable not set")
        keys = [key.strip() for key in keys_env.split(',') if key.strip()]
        if not keys:
            raise ValueError("No valid API keys found in VT_API_KEYS")
        return keys

class ColorPrinter:
    def __init__(self):
        self.c = Config.COLORS

    def _print(self, type_color, type_name, msg):
        print(f"{self.c[type_color]}[{type_name}]{self.c['reset']} {msg}")

    def info(self, msg): self._print('blue', 'INFO', msg)
    def success(self, msg): self._print('green', 'SUCCESS', msg)
    def warning(self, msg): self._print('yellow', 'WARN', msg)
    def error(self, msg): self._print('red', 'ERROR', msg)

    def loop_status(self, domain, queue_len):
        print(f"\n{self.c['magenta']}[LOOP]{self.c['reset']} Popped: {self.c['cyan']}{domain}{self.c['reset']} | Remaining: {queue_len}")

    def fetch_start(self, domain, key_partial):
        print(f"  {self.c['blue']}-> [FETCHING]{self.c['reset']} {domain} (Key: ..{key_partial})")

    def parsing_start(self):
        print(f"  {self.c['yellow']}-> [PARSING]{self.c['reset']} analyzing JSON response...")

    def parse_stats(self, urls, domains):
        print(f"     L Extracted: {self.c['green']}{urls} URLs{self.c['reset']} and {self.c['cyan']}{domains} Domains{self.c['reset']}")

    def queue_add(self, domain):
        print(f"  {self.c['grey']}[QUEUEING]{self.c['reset']} Adding: {domain}")

    def skip_duplicate(self, domain):
        print(f"  {self.c['grey']}[SKIPPING]{self.c['reset']} Already seen: {domain}")

    def url_found(self, url):
        print(f"  {self.c['green']}[URL]{self.c['reset']} {url}")

    def pause_info(self):
        print(f"\n{self.c['yellow']}[PAUSE]{self.c['reset']} Press Enter to continue or 'q' to quit...")

    def resume_info(self):
        print(f"{self.c['green']}[RESUME]{self.c['reset']} Continuing scan...")

    def stats_info(self, urls, domains_processed, queue_size):
        print(f"{self.c['cyan']}[STATS]{self.c['reset']} URLs: {urls} | Domains: {domains_processed} | Queue: {queue_size}")

    def cooldown_wait(self, seconds, domain, retry_count):
        print(f"{self.c['yellow']}[COOLDOWN]{self.c['reset']} Retry {retry_count}/{Config.MAX_RETRIES} for {domain}. Waiting {seconds}s...")

    def max_retries_exceeded(self, domain):
        print(f"{self.c['red']}[MAX_RETRIES]{self.c['reset']} Skipping {domain} after {Config.MAX_RETRIES} failed attempts")

    def scan_complete(self):
        print(f"\n{self.c['green']}{'='*60}{self.c['reset']}")
        print(f"{self.c['green']}    SCAN COMPLETED SUCCESSFULLY!{self.c['reset']}")
        print(f"{self.c['green']}{'='*60}{self.c['reset']}")

class VirusTotalAPI:
    def __init__(self, printer):
        self.printer = printer
        self.api_keys = Config.get_api_keys()
        self.key_iterator = cycle(self.api_keys)

    def fetch_report(self, domain):
        for attempt in range(len(self.api_keys)):
            key = next(self.key_iterator)
            self.printer.fetch_start(domain, key[-6:])

            try:
                resp = requests.get(
                    Config.API_URL,
                    params={'apikey': key, 'domain': domain},
                    timeout=Config.TIMEOUT
                )

                if resp.status_code == 200:
                    data = resp.json()
                    if data and not data.get('error'):
                        return data
                    else:
                        error_msg = data.get('verbose_msg', 'Unknown API error')
                        self.printer.warning(f"API error for {domain}: {error_msg}")

                self.printer.warning(f"Key ..{key[-6:]} failed ({resp.status_code}). Rotating...")

            except requests.RequestException as e:
                self.printer.error(f"Request failed: {e}")

        return None

class ResponseParser:
    @staticmethod
    def parse(data, current_domain=None):
        if not data: return set(), set()

        urls = ResponseParser._get_all_urls(data)
        domains = ResponseParser._get_domains(data)

        url_domains = ResponseParser._extract_domains_from_urls(urls)
        domains.update(url_domains)

        return urls, domains

    @staticmethod
    def _get_all_urls(data):
        urls = set()
        for field in ['detected_urls', 'undetected_urls']:
            for item in data.get(field, []):
                url = item[0] if isinstance(item, list) and len(item) > 0 else \
                      item.get('url') if isinstance(item, dict) else \
                      item if isinstance(item, str) else None

                if url and isinstance(url, str) and url.strip():
                    urls.add(url.strip())
        return urls

    @staticmethod
    def _get_domains(data):
        domains = set()
        for field in ['subdomains', 'domain_siblings']:
            for domain in data.get(field, []):
                domain = domain.strip()
                if domain and ResponseParser._is_valid_domain(domain):
                    domains.add(domain)
        return domains

    @staticmethod
    def _extract_domains_from_urls(urls):
        domains = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    domains.add(parsed.netloc)
                elif not parsed.scheme and '.' in url:
                    domains.add(url.split('/')[0])
            except:
                continue
        return domains

    @staticmethod
    def _is_valid_domain(domain):

        if not domain or len(domain) > 253:
            return False
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        return bool(re.match(pattern, domain))

class DomainScanner:
    def __init__(self):
        self.printer = ColorPrinter()
        self.api = VirusTotalAPI(self.printer)
        self.queue = deque()
        self.history = set()
        self.seen = set()
        self.unique_urls = set()
        self.paused = False
        self.should_stop = False
        self.retry_count = {}
        self.lock = threading.Lock()

    def run(self, target, output):
        if not ResponseParser._is_valid_domain(target):
            self.printer.error(f"Invalid target: {target}")
            return

        self.queue.append(target)
        self.seen.add(target)

        self.printer.info(f"Target: {target} | Keys: {len(self.api.api_keys)} | Output: {output}")
        self.printer.info("Press ENTER to pause")

        self._start_input_listener()

        try:
            while self.queue and not self.should_stop:
                if self.paused:
                    self._handle_pause()
                    if self.should_stop: break

                current = self.queue.popleft()
                if current in self.history:
                    self.printer.skip_duplicate(current)
                    continue

                self.printer.loop_status(current, len(self.queue))
                self._process(current)

        except KeyboardInterrupt:
            self.printer.warning("Scan interrupted")

        self._save(output)
        self.printer.scan_complete()
        self.printer.success(f"Scan finished. {len(self.unique_urls)} URLs saved.")
        self.printer.stats_info(len(self.unique_urls), len(self.history), len(self.queue))

    def _start_input_listener(self):
        def listen():
            while not self.should_stop:
                try:
                    if input().strip() == '':
                        with self.lock:
                            if not self.paused:
                                self.paused = True
                except:
                    pass

        self.input_thread = threading.Thread(target=listen, daemon=True)
        self.input_thread.start()

    def pause_scan(self):
        with self.lock:
            if not self.paused:
                self.paused = True

    def _handle_pause(self):
        self.printer.pause_info()
        while self.paused and not self.should_stop:
            try:
                cmd = input().strip().lower()
                if cmd == 'q':
                    self.should_stop = True
                    self.printer.warning("Quitting...")
                elif cmd == '':
                    with self.lock:
                        self.paused = False
                    self.printer.resume_info()
                    self.printer.stats_info(len(self.unique_urls), len(self.history), len(self.queue))
            except:
                pass

    def _process(self, domain):
        data = self.api.fetch_report(domain)

        if data is None:
            current_retries = self.retry_count.get(domain, 0) + 1
            self.retry_count[domain] = current_retries

            if current_retries >= Config.MAX_RETRIES:
                self.printer.max_retries_exceeded(domain)
                self.history.add(domain)
                return

            self.printer.cooldown_wait(Config.COOLDOWN, domain, current_retries)
            self.queue.appendleft(domain)
            time.sleep(Config.COOLDOWN)
            return

        if domain in self.retry_count:
            del self.retry_count[domain]

        self.history.add(domain)
        self.printer.parsing_start()

        new_urls, new_domains = ResponseParser.parse(data, domain)
        self.printer.parse_stats(len(new_urls), len(new_domains))

        for url in new_urls:
            if url not in self.unique_urls:
                self.printer.url_found(url)
                self.unique_urls.add(url)

        for d in new_domains:
            if d not in self.history and d not in self.seen:
                self.printer.queue_add(d)
                self.queue.append(d)
                self.seen.add(d)

    def _save(self, path):
        try:
            with open(path, "w", encoding='utf-8') as f:
                f.write("\n".join(sorted(self.unique_urls)))
            self.printer.success(f"Results saved to {path}")
        except IOError as e:
            self.printer.error(f"Save failed: {e}")

def main():
    print_logo()

    parser = argparse.ArgumentParser(description="VirusTotal Domain Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target Domain")
    parser.add_argument("-o", "--output", default="results.txt", help="Output File")
    args = parser.parse_args()

    try:
        DomainScanner().run(args.url, args.output)
    except ValueError as e:
        print(f"Error: {e}")
        print("Set API keys: export VT_API_KEYS=\"key1,key2,key3\"")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
