# VT Domain Reconnaissance (VT-Recon)

**VT-Recon (v1.3)** is a highly dynamic, recursive intelligence-gathering tool that maps target URLs and associated subdomains via the VirusTotal API. It systematically discovers infrastructure by pivoting through domain reports, seamlessly handling API rate limits, automatically rotating keys, and dynamically filtering scan queues on the fly.

##  What's New in v1.3 
* **⚡ Pipeline Ready (`-pipe`):** Strips visual output and color so you can pipe results directly into other security tools. 
* **📂 Bulk Domain Loading (`-l`):** Pass a `.txt` list of domains instead of a single URL to scan vast amounts of infrastructure at once.
* **🎯 Granular Recursion (`-r`):** Dictate exactly what gets queued. Choose to recurse strictly on a root domain, a wildcard sub-level (`*.sub.example.com`), or scrape `all` targets.
* **⚙️ Runtime Configuration:** Pause the scan and inject dynamic arguments (like toggling timestamps or changing recursion targets) without dropping your current progress.

---

## ⚙️ How It Works

1. **Domain Lookup (Initial Query):**
   The script queries the VirusTotal API `domain/report` endpoint for your target domain(s).

2. **Data Extraction & Parsing:**
   The JSON response is analyzed to extract:
   * **URLs Found:** `detected_urls` and `undetected_urls`.
   * **Timestamps:** The specific scan date associated with each URL.
   * **Domain Relationships:** Identifies `subdomains` and `domain_siblings`.

3. **Recursion & Filtering:**
   * Saves unique URLs (and optionally dates) to your output file.
   * Compares newly found domains against your specific recursion rules (`-r`) before adding them to the queue.
   * Maintains a strict history limit to prevent infinite loops.

4. **Repeat:**
   Pops the next valid domain from the queue and repeats the cycle until the queue is exhausted or manually interrupted.

---

## 🔑 Key Features
* **Multi-Key API Rotation:** Automatically cycles through an array of API keys to maximize your throughput and keep scans moving.
* **Rate Limit Handling:** Triggers a visual `65s` cooldown if all your provided keys hit the standard 4 requests/minute limit. Keys invalidating or hitting strict quotas are dynamically disabled for 24 hours.
* **Advanced Interactive Control:**
  * Press `ENTER` to **Pause/Resume** the scan at any time.
  * *While Paused:* Type dynamic arguments (e.g., `-r subs.example.xyz -dt`) and press `ENTER` to update the scan parameters.
  * Press `q` (while paused or running) to safely save your progress and quit.

<img width="732" height="95" alt="image" src="https://github.com/user-attachments/assets/eb5085f4-585c-49f1-ad41-cffc3988acdf" />

---

## 🛠️ Installation

1. **Install dependencies:**
   ```bash
   pip3 install requests
   ```



2. **Set up your VirusTotal API keys:**
Export your keys as an environment variable (comma-separated):
```bash
export VT_API_KEYS="your_key1,your_key2,your_key3"
```


*Note: Supports both Public and Premium keys. Add multiple keys for exponentially better performance. Please refer to the official documentation on [Public vs. Premium API](https://docs.virustotal.com/reference/public-vs-premium-api) limits to understand your quota.*

---

## 💻 Usage

```
options:
  -h, --help               - Show this help message and exit
  -u, --url URL            - Target Domain(s) comma-separated
  -l, --list LIST          - File containing list of domains (.txt)
  -o, --output OUTPUT      - Output File for URLs
  -s, --subdomains FILE    - Output File for retrieved Subdomains
  -r all                   - Target domain for recursive scraping
  -r subs.subs.example.xyz - Specifically recurse all subdomains of target subdomain
  -dt                      - Include date/timestamp
  -pipe                    - remove verbosity to pipe with other tools (httpx, gau, nuclei etc.)
```

### Basic Single Target

```bash
python3 vt_recon.py -u example.com -o results.txt 
```
### Recursively scan all subdomains and `-s output` outputs all discovered subdomains in seprate txt file
```
python3 vt_recon.py -u example.xyz -r all -o results.txt -s gathered-subdomains.txt
```
### Bulk Processing & Timestamps

Load targets from a file and include scan dates in the output:

```bash
python3 vt_recon.py -l domains.txt -o results.txt -dt

```

### Specific Recursion

Filter the queue to only recursively scan subdomains of a specific target:

```bash
python3 vt_recon.py -u example.xyz -r othersub.sub.example.xyz -o urls.txt 
```

### Pipeline Mode 

Remove output verbosity to pipe with other tools (httpx, gau, nuclei etc.)

```bash
python3 vt_recon.py -u example.xyz -pipe | httpx-toolkit -mc 200
```

## `android://` or `oid://` URI Scheme Fetching

You can use VT-Recon to scrape infrastructure related to specific mobile applications via their package names.

https://play.google.com/store/apps/details?id=com.[redacted].android

```bash
python3 vt_recon.py -u com.[redacted].android -o results.txt

```


## ⚠️ Disclaimer

* This script is designed to help security professionals and researchers gather intelligence on their own infrastructure and is intended strictly for educational and security research.
* Users are responsible for adhering to the VirusTotal API Terms of Service.
* Please use this tool wisely. Recursive mapping generates multiple requests and can rapidly consume your VirusTotal API quota.
