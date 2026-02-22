import requests
import time
import argparse
import os
import re
import threading
import sys
import shlex
from collections import deque
from urllib.parse import urlparse

def print_logo(pipe_mode=False):
    if pipe_mode:
        return

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
    print(f"{CYAN}   [+]{RESET} Tool       : {BOLD}VT Domain Reconnaissance{RESET}")
    print(f"{CYAN}   [+]{RESET} Version    : {BOLD}1.3{RESET}")
    print(f"{CYAN}   [+]{RESET} Dev        : {BOLD}Luxiel{RESET}")
    print(f"{CYAN}   [+]{RESET} Github     : {BOLD}https://github.com/0xLuxieL/VT-Recon{RESET}")
    print(f"\n{PURPLE}   ============================================={RESET}\n")

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
            raise ValueError("VT_API_KEYS environment variable not set. E.g., export VT_API_KEYS=\"key1,key2\"")
        keys = [key.strip() for key in keys_env.split(',') if key.strip()]
        if not keys:
            raise ValueError("No valid API keys found in VT_API_KEYS")
        return keys

class ColorPrinter:
    def __init__(self, pipe_mode=False):
        self.c = Config.COLORS
        self.pipe_mode = pipe_mode

    def _print(self, type_color, type_name, msg):
        if self.pipe_mode: return
        sys.stdout.write(f"{self.c[type_color]}[{type_name}]{self.c['reset']} {msg}\n")
        sys.stdout.flush()

    def info(self, msg): self._print('blue', 'INFO', msg)
    def success(self, msg): self._print('green', 'SUCCESS', msg)
    def warning(self, msg): self._print('yellow', 'WARN', msg)

    def error(self, msg):
        sys.stderr.write(f"{self.c['red']}[ERROR]{self.c['reset']} {msg}\n")
        sys.stderr.flush()

    def loop_status(self, domain, queue_len):
        if self.pipe_mode: return
        sys.stdout.write(f"\n{self.c['magenta']}[LOOP]{self.c['reset']} Popped: {self.c['cyan']}{domain}{self.c['reset']} | Remaining: {queue_len}\n")
        sys.stdout.flush()

    def fetch_start(self, domain, key_partial):
        if self.pipe_mode: return
        print(f"  {self.c['blue']}-> [FETCHING]{self.c['reset']} {domain} (Key: ..{key_partial})")

    def parsing_start(self):
        if self.pipe_mode: return
        print(f"  {self.c['yellow']}-> [PARSING]{self.c['reset']} analyzing JSON response...")

    def parse_stats(self, urls, domains):
        if self.pipe_mode: return
        print(f"      L Extracted: {self.c['green']}{urls} URLs{self.c['reset']} and {self.c['cyan']}{domains} Domains{self.c['reset']}")

    def queue_add(self, domain):
        if self.pipe_mode: return
        print(f"  {self.c['grey']}[QUEUEING]{self.c['reset']} Adding: {domain}")

    def skip_duplicate(self, domain):
        if self.pipe_mode: return
        print(f"  {self.c['grey']}[SKIPPING]{self.c['reset']} Already seen: {domain}")

    def url_found(self, url, date, show_dt):
        if self.pipe_mode:
            if show_dt:
                sys.stdout.write(f"{date} | {url}\n")
            else:
                sys.stdout.write(f"{url}\n")
            sys.stdout.flush()
        else:
            if show_dt:
                print(f"  {self.c['green']}[URL]{self.c['reset']} {url} {self.c['grey']}({date}){self.c['reset']}")
            else:
                print(f"  {self.c['green']}[URL]{self.c['reset']} {url}")

    def pause_info(self):
        if self.pipe_mode: return
        sys.stdout.write(f"\n{self.c['yellow']}[PAUSED]{self.c['reset']} Scan paused.\n")
        sys.stdout.write(f"  -> Press {self.c['bold']}ENTER{self.c['reset']} to resume or type {self.c['bold']}'q'{self.c['reset']} to quit.\n")
        sys.stdout.write(f"  -> Or type (e.g. {self.c['bold']}-r subs.example.xyz -dt{self.c['reset']}) and press ENTER to apply & resume.\n> ")
        sys.stdout.flush()

    def resume_info(self):
        if self.pipe_mode: return
        sys.stdout.write(f"{self.c['green']}[RESUME]{self.c['reset']} Resuming scan...\n")
        sys.stdout.flush()

    def stats_info(self, urls, domains_processed, queue_size):
        if self.pipe_mode: return
        print(f"{self.c['cyan']}[STATS]{self.c['reset']} URLs: {urls} | Domains: {domains_processed} | Queue: {queue_size}")

    def cooldown_start_pipe(self, wait_time):
        sys.stderr.write(f"{self.c['yellow']}[VT-RECON COOLDOWN]{self.c['reset']} All keys rate-limited. Pausing for {wait_time}s...\n")
        sys.stderr.flush()

    def cooldown_update(self, remaining):
        if self.pipe_mode: return
        sys.stdout.write(f"\r{self.c['yellow']}[COOLDOWN]{self.c['reset']} All keys exhausted. Waiting... {self.c['bold']}{remaining}s{self.c['reset']}   ")
        sys.stdout.flush()

    def cooldown_done(self):
        if self.pipe_mode: return
        sys.stdout.write("\n")
        sys.stdout.flush()

    def max_retries_exceeded(self, domain):
        if self.pipe_mode:
            sys.stderr.write(f"{self.c['red']}[VT-RECON SKIP]{self.c['reset']} Max retries exceeded for {domain}\n")
            sys.stderr.flush()
        else:
            print(f"{self.c['red']}[MAX_RETRIES]{self.c['reset']} Skipping {domain} after {Config.MAX_RETRIES} failed attempts")

    def scan_complete(self):
        if self.pipe_mode: return
        print(f"\n{self.c['green']}{'='*60}{self.c['reset']}")
        print(f"{self.c['green']}    SCAN COMPLETED SUCCESSFULLY!{self.c['reset']}")
        print(f"{self.c['green']}{'='*60}{self.c['reset']}")


class VirusTotalAPI:
    def __init__(self, printer):
        self.printer = printer
        self.api_keys = [{'key': k, 'ready_at': 0.0} for k in Config.get_api_keys()]

    def fetch_report(self, domain, scanner):
        while not scanner.should_stop:
            scanner.wait_if_paused()

            self.api_keys.sort(key=lambda x: x['ready_at'])
            best_key = self.api_keys[0]
            now = time.time()

            if best_key['ready_at'] > now:
                wait_time = int(best_key['ready_at'] - now)

                if scanner.pipe_mode:
                    self.printer.cooldown_start_pipe(wait_time)

                while time.time() < best_key['ready_at'] and not scanner.should_stop:
                    scanner.wait_if_paused()
                    remaining = int(best_key['ready_at'] - time.time())
                    if remaining < 0: remaining = 0

                    if not scanner.pipe_mode:
                        self.printer.cooldown_update(remaining)

                    time.sleep(0.5)

                if not scanner.pipe_mode and wait_time > 0:
                    self.printer.cooldown_done()

            if scanner.should_stop:
                return None

            key = best_key['key']
            self.printer.fetch_start(domain, key[-6:])

            try:
                resp = requests.get(
                    Config.API_URL,
                    params={'apikey': key, 'domain': domain},
                    timeout=Config.TIMEOUT
                )

                if resp.status_code == 200:
                    time.sleep(1)
                    try:
                        data = resp.json()
                        if data and not data.get('error'):
                            return data
                        else:
                            error_msg = data.get('verbose_msg', 'Unknown API error')
                            self.printer.warning(f"API error for {domain}: {error_msg}")
                            return None
                    except ValueError:
                        self.printer.warning(f"Failed to parse JSON for {domain} (Proxy/WAF issue).")
                        return None

                elif resp.status_code == 204:
                    self.printer.warning(f"Key ..{key[-6:]} rate limited (204). Rotating...")
                    best_key['ready_at'] = time.time() + Config.COOLDOWN
                    continue

                elif resp.status_code in [401, 403]:
                    self.printer.warning(f"Key ..{key[-6:]} invalid or quota exceeded (403). Disabling key.")
                    best_key['ready_at'] = time.time() + 86400
                    continue

                else:
                    self.printer.warning(f"Key ..{key[-6:]} failed with status {resp.status_code}.")
                    return None

            except requests.exceptions.ConnectionError:
                self.printer.error(f"Network error! Check your internet connection. Retrying in 3s...")
                time.sleep(3)
            except requests.RequestException as e:
                self.printer.error(f"Request failed: {e}")
                return None

        return None


class ResponseParser:
    _DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$')

    @staticmethod
    def parse(data):
        if not data: return set(), set()

        url_data = ResponseParser._get_all_urls(data)
        domains = ResponseParser._get_domains(data)

        just_urls = {u[0] for u in url_data}
        url_domains = ResponseParser._extract_domains_from_urls(just_urls)

        valid_url_domains = {d for d in url_domains if ResponseParser._is_valid_domain(d)}
        domains.update(valid_url_domains)

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
                try:
                    domain = domain.encode('idna').decode('ascii')
                except Exception:
                    pass
                if domain and ResponseParser._is_valid_domain(domain):
                    domains.add(domain)
        return domains

    @staticmethod
    def _extract_domains_from_urls(urls):
        domains = set()
        for url in urls:
            try:
                extracted = None
                if "://" in url:
                    extracted = url.split("://", 1)[1].split('/', 1)[0]
                else:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        extracted = parsed.netloc
                    elif parsed.scheme and ":" in url:
                        part = url.split(":", 1)[1]
                        extracted = part.split('/', 1)[0]
                    elif not parsed.scheme and '.' in url:
                        extracted = url.split('/', 1)[0]

                if extracted:
                    if "@" in extracted:
                        extracted = extracted.split("@", 1)[1]
                    if ":" in extracted:
                        extracted = extracted.split(":", 1)[0]

                    extracted = extracted.encode('idna').decode('ascii')
                    domains.add(extracted)
            except Exception:
                continue
        return domains

    @staticmethod
    def _is_valid_domain(domain):
        if not domain or len(domain) > 253: return False
        return bool(ResponseParser._DOMAIN_REGEX.match(domain))


class DomainScanner:
    def __init__(self, pipe_mode=False):
        self.pipe_mode = pipe_mode
        self.printer = ColorPrinter(self.pipe_mode)
        self.api = VirusTotalAPI(self.printer)

        self.queue = deque()
        self.history = set()
        self.seen = set()
        self.unique_urls = {}

        self.paused = False
        self.should_stop = False
        self.retry_count = {}

        self.state_lock = threading.Lock()

        self.recursive = None
        self.show_dt = False

    def wait_if_paused(self):
        while True:
            with self.state_lock:
                is_paused = self.paused
                should_stop = self.should_stop

            if should_stop: return
            if not is_paused: break
            time.sleep(0.1)

    def run(self, targets, output, subdomains_output=None, recursive=None, show_dt=False):
        self.recursive = recursive
        self.show_dt = show_dt

        if self.pipe_mode and self.show_dt:
            self.show_dt = False

        for target in targets:
            clean_target = target.strip()

            if "://" in clean_target:
                clean_target = clean_target.split("://", 1)[1]

            clean_target = clean_target.split('/')[0].split('?')[0].split('#')[0]

            if "@" in clean_target:
                clean_target = clean_target.split("@", 1)[1]

            if ":" in clean_target:
                clean_target = clean_target.split(":", 1)[0]

            try:
                clean_target = clean_target.encode('idna').decode('ascii')
            except Exception:
                pass

            if not ResponseParser._is_valid_domain(clean_target):
                self.printer.error(f"Invalid target domain skipped: {target}")
                continue

            if clean_target in self.seen:
                continue

            self.queue.append(clean_target)
            self.seen.add(clean_target)

        if not self.queue:
            self.printer.error("No valid targets remained after validation. Exiting.")
            sys.exit(1)

        try:
            if not os.path.exists(output) or os.path.getsize(output) == 0:
                with open(output, "a", encoding='utf-8') as f:
                    f.write(f"# Scan Results Initialized\n")
            else:
                with open(output, "a", encoding='utf-8') as f: pass
        except IOError as e:
            self.printer.error(f"Cannot write to output file '{output}': {e}")
            sys.exit(1)

        if subdomains_output:
            try:
                with open(subdomains_output, "a", encoding='utf-8') as f:
                    pass
            except IOError as e:
                self.printer.error(f"Cannot write to subdomain file '{subdomains_output}': {e}")
                sys.exit(1)

        self.printer.info(f"Targets Loaded: {len(self.queue)} | Keys: {len(self.api.api_keys)}")
        self.printer.info("Press [ENTER] to pause the scan dynamically")

        self._start_input_monitor()

        try:
            while self.queue and not self.should_stop:
                self.wait_if_paused()

                domain = self.queue.popleft()

                if domain in self.history:
                    continue

                self.printer.loop_status(domain, len(self.queue))
                self._process(domain)

        except KeyboardInterrupt:
            self.printer.error("Scan interrupted by Keyboard")
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

        sys.exit(0)

    def _filter_queue_for_new_target(self):
        if not self.recursive or self.recursive.lower() == 'all':
            return

        rec_val = self.recursive.lower()
        new_queue = deque()

        with self.state_lock:
            while self.queue:
                d = self.queue.popleft()
                keep = False

                if rec_val.startswith('*.'):
                    suffix = rec_val[1:]
                    if d.lower().endswith(suffix) or d.lower() == suffix[1:]:
                        keep = True
                else:
                    if d.lower() == rec_val or d.lower().endswith('.' + rec_val):
                        keep = True

                if keep:
                    new_queue.append(d)

            self.queue = new_queue

            target_domain = rec_val[2:] if rec_val.startswith('*.') else rec_val
            if target_domain not in self.seen:
                self.queue.appendleft(target_domain)
                self.seen.add(target_domain)
                self.printer.info(f"Auto-injected new pivot target: {target_domain}")

        self.printer.info(f"Queue purged of old domains. New backlog size: {len(self.queue)}")

    def _apply_dynamic_args(self, cmd_str):
        try:
            args = shlex.split(cmd_str)
        except ValueError:
            args = cmd_str.split()

        i = 0
        while i < len(args):
            token = args[i].lower()
            if token in ['-dt', '--datetime']:
                self.show_dt = not self.show_dt
                state = "enabled" if self.show_dt else "disabled"
                self.printer.success(f"Config updated: DateTime (-dt) {state}.")
            elif token in ['-r', '--recursive']:
                if i + 1 < len(args):
                    self.recursive = args[i+1]
                    self.printer.success(f"Config updated: Recursive target set to '{self.recursive}'")
                    self._filter_queue_for_new_target()
                    i += 1
                else:
                    self.printer.warning("Missing value for -r. Ignored.")
            else:
                self.printer.warning(f"Unknown dynamic argument ignored: {args[i]}")
            i += 1

    def _start_input_monitor(self):
        if self.pipe_mode:
            return

        def monitor():
            if not sys.stdin.isatty(): return
            while not self.should_stop:
                try:
                    cmd = input().strip()

                    if self.should_stop: break

                    if cmd.lower() == 'q':
                        with self.state_lock:
                            self.should_stop = True
                        self.printer.warning("Quitting requested...")
                        break

                    with self.state_lock:
                        is_paused = self.paused

                    if not is_paused:
                        with self.state_lock:
                            self.paused = True
                        self.printer.pause_info()
                    else:
                        if cmd != '':
                            self._apply_dynamic_args(cmd)

                        with self.state_lock:
                            self.paused = False

                        self.printer.resume_info()
                        self.printer.stats_info(len(self.unique_urls), len(self.history), len(self.queue))

                except (EOFError, Exception):
                    break

        t = threading.Thread(target=monitor, daemon=True)
        t.start()

    def _process(self, domain):
        if self.should_stop: return
        self.wait_if_paused()

        data = self.api.fetch_report(domain, self)

        if data is None and not self.should_stop:
            current_retries = self.retry_count.get(domain, 0) + 1
            self.retry_count[domain] = current_retries

            if current_retries >= Config.MAX_RETRIES:
                self.printer.max_retries_exceeded(domain)
                self.history.add(domain)
                return

            self.queue.append(domain)
            return

        if self.should_stop: return

        if data.get('response_code') == 0:
            self.printer.warning(f"Domain not found in VT database: {domain}")
            self.history.add(domain)
            if domain in self.retry_count:
                del self.retry_count[domain]
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
                self.printer.url_found(url, date, self.show_dt)
                self.unique_urls[url] = date

        for d in new_domains:
            if d in self.seen:
                continue

            self.seen.add(d)
            should_queue = False

            if self.recursive:
                rec_val = self.recursive.lower()
                if rec_val == 'all':
                    should_queue = True
                else:
                    if rec_val.startswith('*.'):
                        suffix = rec_val[1:]
                        if d.lower().endswith(suffix) or d.lower() == suffix[1:]:
                            should_queue = True
                    else:
                        if d.lower() == rec_val or d.lower().endswith('.' + rec_val):
                            should_queue = True

            if should_queue:
                if len(self.queue) < 100000:
                    self.printer.queue_add(d)
                    self.queue.append(d)
                else:
                    self.printer.warning(f"Queue cap reached! Skipping recursion for: {d}")

    def _save(self, url_path, subdomain_path=None):
        try:
            with open(url_path, "a", encoding='utf-8') as f:
                for url in sorted(self.unique_urls.keys()):
                    date = self.unique_urls[url]
                    if self.show_dt:
                        f.write(f"{date} | {url}\n")
                    else:
                        f.write(f"{url}\n")
            if not self.pipe_mode:
                self.printer.success(f"Results appended to {url_path}")
        except IOError as e:
            self.printer.error(f"URL Save failed: {e}")

        if subdomain_path:
            try:
                with open(subdomain_path, "w", encoding='utf-8') as f:
                    f.write("\n".join(sorted(self.seen)))
                if not self.pipe_mode:
                    self.printer.success(f"Subdomains saved to {subdomain_path}")
            except IOError as e:
                self.printer.error(f"Subdomain Save failed: {e}")


class CustomParser(argparse.ArgumentParser):
    def print_help(self):
        print("usage: python3 vt_recon.py [-u example.xyz] [-l domains.txt] [-o results.txt] [-s subdomains.txt] [-r all] [-dt] [-pipe]\n")
        print("VirusTotal Domain Scanner v1.3 \n")
        print("options:")
        print("  -h, --help               - Show this help message and exit")
        print("  -u, --url URL            - Target Domain(s) comma-separated")
        print("  -l, --list LIST          - File containing list of domains (.txt)")
        print("  -o, --output OUTPUT      - Output File for URLs")
        print("  -s, --subdomains FILE    - Output File for retrieved Subdomains")
        print("  -r all                   - Target domain for recursive scraping")
        print("  -r subs.subs.example.xyz - Specifically recurse all subdomains of target subdomain")
        print("  -dt                      - Include date/timestamp")
        print("  -pipe                    - remove verbosity to pipe with other tools (httpx, gau, nuclei etc.)")

    def error(self, message):
        sys.stderr.write(f"\n\033[91m[ERROR]\033[0m \033[1mMissing Target Domain(s)!\033[0m\n")
        sys.stderr.write(f"        Please provide targets using either \033[96m-u target.com\033[0m  or \033[96m-l domains.txt\033[0m\n\n")
        self.print_help()
        sys.exit(2)


def main():
    pipe_mode = '-pipe' in sys.argv
    help_requested = '-h' in sys.argv or '--help' in sys.argv

    if not pipe_mode and not help_requested:
        print_logo(pipe_mode)
    elif help_requested:
        print_logo(pipe_mode)

    parser = CustomParser(add_help=False)
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-u", "--url")
    parser.add_argument("-l", "--list")
    parser.add_argument("-o", "--output", default="results.txt")
    parser.add_argument("-s", "--subdomains")
    parser.add_argument("-r", "--recursive")
    parser.add_argument("-dt", "--datetime", action="store_true")
    parser.add_argument("-pipe", action="store_true")

    args = parser.parse_args()

    if args.help:
        parser.print_help()
        sys.exit(0)

    targets = []

    if args.url:
        targets.extend([t.strip() for t in args.url.split(',') if t.strip()])

    if args.list:
        if os.path.exists(args.list):
            try:
                with open(args.list, 'r', encoding='utf-8') as f:
                    targets.extend([line.strip() for line in f if line.strip()])
            except IOError as e:
                sys.stderr.write(f"\n\033[91m[ERROR]\033[0m Error reading list file: {e}\n")
                sys.exit(1)
        else:
            sys.stderr.write(f"\n\033[91m[ERROR]\033[0m List file '{args.list}' not found.\n")
            sys.exit(1)

    if not targets:
        parser.error("argument -u --url: expected target domain")

    unique_targets = list(dict.fromkeys(targets))

    try:
        scanner = DomainScanner(pipe_mode=args.pipe)
        scanner.run(unique_targets, args.output, args.subdomains, args.recursive, args.datetime)
    except ValueError as e:
        sys.stderr.write(f"\n\033[91m[ERROR]\033[0m {e}\n")
        sys.stderr.write("        Set API keys: export VT_API_KEYS=\"key1,key2,key3\"\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"\n\033[91m[ERROR]\033[0m Unexpected error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
