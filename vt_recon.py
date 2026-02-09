import requests
import time
import argparse
import os
import re
import threading
import sys
from collections import deque
from itertools import cycle
from urllib.parse import urlparse

def print_logo():
    CYAN = "\033[96m"
    PURPLE = "\033[95m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

    logo = [
        r" __      __ _________ ____                     ",
        r" \ \    / //__   __| |  _ \ ___  ___ ___  _ __  ",
        r"  \ \  / /    | |    | |_) / _ \/ __/ _ \| '_ \ ",
        r"   \ \/ /     | |    |  _ <  __/ (_| (_) | | | |",
        r"    \__/      |_|    |_| \_\___|\___\___/|_| |_|"
    ]

    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n")

    for line in logo:
        time.sleep(0.05)
        print(f"{BOLD}{CYAN}{line[:23]}{PURPLE}{line[23:]}{RESET}")

    print("\n")
    print(f"{CYAN}    [+]{RESET} Tool       : {BOLD}VT Domain Reconnaissance{RESET}")
    print(f"{CYAN}    [+]{RESET} Version    : {BOLD}1.2 {RESET}")
    print(f"{CYAN}    [+]{RESET} Dev        : {BOLD}Luxiel{RESET}")
    print(f"{CYAN}    [+]{RESET} Github     : {BOLD}https://github.com/0xLuxieL/VT-Recon{RESET}")
    print(f"\n{PURPLE}    ============================================={RESET}\n")

class Config:
    API_URL = "https://www.virustotal.com/vtapi/v2/domain/report"
    COOLDOWN = 65
    TIMEOUT = 10
    MAX_RETRIES = 3

    COLORS = {
        'cyan': '\033[96m', 'magenta': '\033[95m', 'green': '\033[92m',
        'yellow': '\033[93m', 'blue': '\033[94m', 'red': '\033[91m',
        'reset': '\033[0m', 'grey': '\033[90m', 'bold': '\033[1m'
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
        self.lock = threading.Lock()

    def _print(self, type_color, type_name, msg):
        with self.lock:
            sys.stdout.write(f"{self.c[type_color]}[{type_name}]{self.c['reset']} {msg}\n")
            sys.stdout.flush()

    def info(self, msg): self._print('blue', 'INFO', msg)
    def success(self, msg): self._print('green', 'SUCCESS', msg)
    def warning(self, msg): self._print('yellow', 'WARN', msg)
    def error(self, msg): self._print('red', 'ERROR', msg)

    def loop_status(self, domain, queue_len):
        with self.lock:
            sys.stdout.write(f"\n{self.c['magenta']}[LOOP]{self.c['reset']} Popped: {self.c['cyan']}{domain}{self.c['reset']} | Remaining: {queue_len}\n")
            sys.stdout.flush()

    def fetch_start(self, domain, key_partial):
        with self.lock:
            print(f"  {self.c['blue']}-> [FETCHING]{self.c['reset']} {domain} (Key: ..{key_partial})")

    def parsing_start(self):
        with self.lock:
            print(f"  {self.c['yellow']}-> [PARSING]{self.c['reset']} analyzing JSON response...")

    def parse_stats(self, urls, domains):
        with self.lock:
            print(f"      L Extracted: {self.c['green']}{urls} URLs{self.c['reset']} and {self.c['cyan']}{domains} Domains{self.c['reset']}")

    def queue_add(self, domain):
        with self.lock:
            print(f"  {self.c['grey']}[QUEUEING]{self.c['reset']} Adding: {domain}")

    def skip_duplicate(self, domain):
        with self.lock:
            print(f"  {self.c['grey']}[SKIPPING]{self.c['reset']} Already seen: {domain}")

    def url_found(self, url, date):
        with self.lock:
            print(f"  {self.c['green']}[URL]{self.c['reset']} {url} {self.c['grey']}({date}){self.c['reset']}")

    def pause_info(self):
        with self.lock:
            sys.stdout.write(f"\n{self.c['yellow']}[PAUSED]{self.c['reset']} Scan paused. Press {self.c['bold']}ENTER{self.c['reset']} to resume or type {self.c['bold']}'q'{self.c['reset']} to quit.\n")
            sys.stdout.flush()

    def resume_info(self):
        with self.lock:
            sys.stdout.write(f"{self.c['green']}[RESUME]{self.c['reset']} Resuming scan...\n")
            sys.stdout.flush()

    def stats_info(self, urls, domains_processed, queue_size):
        with self.lock:
            print(f"{self.c['cyan']}[STATS]{self.c['reset']} URLs: {urls} | Domains: {domains_processed} | Queue: {queue_size}")

    def cooldown_update(self, remaining, domain, retry):
        with self.lock:
            # \r moves cursor to start of line to overwrite
            sys.stdout.write(f"\r{self.c['yellow']}[COOLDOWN]{self.c['reset']} Retry {retry}/{Config.MAX_RETRIES} for {domain}. Waiting... {self.c['bold']}{remaining}s{self.c['reset']}   ")
            sys.stdout.flush()

    def cooldown_done(self):
        with self.lock:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def max_retries_exceeded(self, domain):
        with self.lock:
            print(f"{self.c['red']}[MAX_RETRIES]{self.c['reset']} Skipping {domain} after {Config.MAX_RETRIES} failed attempts")

    def scan_complete(self):
        with self.lock:
            print(f"\n{self.c['green']}{'='*60}{self.c['reset']}")
            print(f"{self.c['green']}    SCAN COMPLETED SUCCESSFULLY!{self.c['reset']}")
            print(f"{self.c['green']}{'='*60}{self.c['reset']}")

class VirusTotalAPI:
    def __init__(self, printer):
        self.printer = printer
        self.api_keys = Config.get_api_keys()
        self.key_iterator = cycle(self.api_keys)

    def fetch_report(self, domain):
        for _ in range(len(self.api_keys)):
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
    def parse(data):
        if not data: return set(), set()

        url_data = ResponseParser._get_all_urls(data)
        domains = ResponseParser._get_domains(data)

        just_urls = {u[0] for u in url_data}
        url_domains = ResponseParser._extract_domains_from_urls(just_urls)
        domains.update(url_domains)

        return url_data, domains

    @staticmethod
    def _get_all_urls(data):
        urls_data = set()
        for field in ['detected_urls', 'undetected_urls']:
            for item in data.get(field, []):
                url = None
                date = "N/A"

                if isinstance(item, list):
                    if len(item) > 0:
                        url = item[0]
                        if len(item) >= 5:
                            date = str(item[4])

                elif isinstance(item, dict):
                    url = item.get('url')
                    date = item.get('scan_date', 'N/A')

                elif isinstance(item, str):
                    url = item

                if url and isinstance(url, str) and url.strip():
                    urls_data.add((url.strip(), date))
        return urls_data

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
            except Exception:
                continue
        return domains

    @staticmethod
    def _is_valid_domain(domain):
        if not domain or len(domain) > 253: return False
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        return bool(re.match(pattern, domain))

class DomainScanner:
    def __init__(self):
        self.printer = ColorPrinter()
        self.api = VirusTotalAPI(self.printer)
        self.queue = deque()
        self.history = set()
        self.seen = set()
        self.unique_urls = {}

        self.paused = False
        self.should_stop = False
        self.retry_count = {}
        self.state_lock = threading.Lock()

    def wait_if_paused(self):
        while True:
            with self.state_lock:
                is_paused = self.paused
                should_stop = self.should_stop

            if should_stop: return
            if not is_paused: break

            time.sleep(0.1)

    def run(self, target, output, subdomains_output=None):
        if not ResponseParser._is_valid_domain(target):
            self.printer.error(f"Invalid target: {target}")
            return

        if not os.path.exists(output):
            with open(output, "w", encoding='utf-8') as f:
                f.write(f"# Scan Results for {target}\n")

        self.queue.append(target)
        self.seen.add(target)

        self.printer.info(f"Target: {target} | Keys: {len(self.api.api_keys)}")
        self.printer.info("Press [ENTER] to pause/resume scan")

        self._start_input_monitor()

        try:
            while self.queue and not self.should_stop:
                self.wait_if_paused()
                if self.should_stop: break

                current = self.queue.popleft()
                if current in self.history:
                    self.printer.skip_duplicate(current)
                    continue

                self.printer.loop_status(current, len(self.queue))
                self._process(current)

        except KeyboardInterrupt:
            self.printer.warning("Scan interrupted by Keyboard")
            self.should_stop = True

        self._save(output, subdomains_output)

        if not self.should_stop:
            self.printer.scan_complete()
            self.printer.success(f"Scan finished. {len(self.unique_urls)} new URLs saved.")
            if subdomains_output:
                self.printer.success(f"Subdomains saved to {subdomains_output}")
            self.printer.stats_info(len(self.unique_urls), len(self.history), len(self.queue))
        else:
             self.printer.warning("Scan terminated early. Partial results saved.")

        os._exit(0)

    def _start_input_monitor(self):
        def monitor():
            if not sys.stdin.isatty(): return
            while not self.should_stop:
                try:
                    cmd = input()

                    if self.should_stop: break
                    cmd = cmd.strip().lower()

                    if cmd == 'q':
                        with self.state_lock:
                            self.should_stop = True
                        self.printer.warning("Quitting requested...")
                        break

                    if cmd == '':
                        with self.state_lock:
                            self.paused = not self.paused
                            is_paused = self.paused

                        if is_paused:
                            self.printer.pause_info()
                        else:
                            self.printer.resume_info()
                            self.printer.stats_info(len(self.unique_urls), len(self.history), len(self.queue))

                except (EOFError, Exception):
                    break
        t = threading.Thread(target=monitor, daemon=True)
        t.start()

    def _process(self, domain):
        if self.should_stop: return
        self.wait_if_paused()

        data = self.api.fetch_report(domain)

        if data is None:
            current_retries = self.retry_count.get(domain, 0) + 1
            self.retry_count[domain] = current_retries

            if current_retries >= Config.MAX_RETRIES:
                self.printer.max_retries_exceeded(domain)
                self.history.add(domain)
                return

            self.queue.appendleft(domain)

            wake_up_time = time.time() + Config.COOLDOWN

            while time.time() < wake_up_time:
                if self.should_stop: return
                self.wait_if_paused()

                remaining = int(wake_up_time - time.time())
                if remaining < 0: remaining = 0

                self.printer.cooldown_update(remaining, domain, current_retries)
                time.sleep(1)

            self.printer.cooldown_done()
            return

        if domain in self.retry_count:
            del self.retry_count[domain]

        self.history.add(domain)

        self.wait_if_paused()
        self.printer.parsing_start()

        new_url_data, new_domains = ResponseParser.parse(data)
        self.printer.parse_stats(len(new_url_data), len(new_domains))

        for url, date in new_url_data:
            if url not in self.unique_urls:
                self.printer.url_found(url, date)
                self.unique_urls[url] = date

        for d in new_domains:
            if d not in self.history and d not in self.seen:
                self.printer.queue_add(d)
                self.queue.append(d)
                self.seen.add(d)

    def _save(self, url_path, subdomain_path=None):
        try:
            with open(url_path, "a", encoding='utf-8') as f:
                for url in sorted(self.unique_urls.keys()):
                    date = self.unique_urls[url]
                    f.write(f"{date} | {url}\n")
            self.printer.success(f"Results appended to {url_path}")
        except IOError as e:
            self.printer.error(f"URL Save failed: {e}")

        if subdomain_path:
            try:
                with open(subdomain_path, "w", encoding='utf-8') as f:
                    f.write("\n".join(sorted(self.seen)))
                self.printer.success(f"Subdomains saved to {subdomain_path}")
            except IOError as e:
                self.printer.error(f"Subdomain Save failed: {e}")

def main():
    print_logo()
    parser = argparse.ArgumentParser(description="VirusTotal Domain Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target Domain")
    parser.add_argument("-o", "--output", default="results.txt", help="Output File for URLs")
    parser.add_argument("-subdomains", help="Output File for retrieved Subdomains")
    args = parser.parse_args()

    try:
        DomainScanner().run(args.url, args.output, args.subdomains)
    except ValueError as e:
        print(f"Error: {e}")
        print("Set API keys: export VT_API_KEYS=\"key1,key2,key3\"")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
