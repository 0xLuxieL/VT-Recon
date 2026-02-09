# VT Domain Reconnaissance

**VT-Recon** is a recursive intelligence gathering tool that maps target URLs and associated subdomains via the VirusTotal API. It systematically discovers infrastructure by pivoting through domain reports, handling API rate limits, and rotating keys automatically.

## New Features (v1.2)
* **📅 Historical Date Parsing:** Now extracts and displays the **scan date** for every URL found, allowing you to see exactly when a specific resource was archived or flagged on VirusTotal.
* **📂 Subdomain Export:** New argument `-subdomains` allows you to save a separate clean list of all discovered subdomains.
* **⏱️ Visual Timer:** Added a visual countdown timer for API cooldowns.

---

## ⚙️ How It Works

1.  **Domain Lookup (Initial Query):**
    The script queries the VirusTotal API `domain/report` endpoint for the target domain.

2.  **Data Extraction & Parsing:**
    The JSON response is analyzed to extract:
    * **URLs Found:** `detected_urls` and `undetected_urls`.
    * **Timestamps:** The specific scan date associated with each URL.
    * **Domain Relationships:** `subdomains` and `domain_siblings`.

3.  **Recursion & De-duplication:**
    * Saves unique URLs + Dates to your output file.
    * Queues new domains/siblings for recursion.
    * Maintains a history to prevent infinite loops.

4.  **Repeat:**
    The script pops the next domain from the queue and repeats the cycle until the queue is empty or the user stops the scan.

---

## 🔑 Key Features
* **API Key Rotation:** Automatically cycles through multiple API keys to maximize throughput.
* **Rate Limit Handling:** Triggers a `65s` visual cooldown if all keys hit the standard 4 requests/minute limit.
* **Interactive Control:** Press `ENTER` to **Pause/Resume** the scan at any time.
<img width="411" alt="pause" src="https://github.com/user-attachments/assets/1456b238-a27e-49ce-b0ae-84b6d3daa03b" />

* **Press** `q` (while paused or running) to save progress and quit.

<img width="747" alt="q" src="https://github.com/user-attachments/assets/9b1b6cf0-dbc5-46e4-bacd-67c389982b3e" />

---

##  Installation

1.  **Install dependencies:**
    ```bash
    pip3 install requests
    ```

2.  **Set up your VirusTotal API keys:**
    Export your keys as an environment variable (comma-separated):
    ```bash
    export VT_API_KEYS="your_key1,your_key2,your_key3"
    ```
    *Note: Supports both Public and Premium keys. Add multiple keys for better performance. Please refer to the official documentation on [Public vs. Premium API](https://docs.virustotal.com/reference/public-vs-premium-api) limits to understand your quota.*
     

---

## 💻 Usage
```bash
python3 vt_recon.py -u example.com -o results.txt -s subdomains.txt
```

https://github.com/user-attachments/assets/744155a8-8f3b-40a5-90f4-8dd446dd7304

## `android://` or `oid://` URI scheme fetching 

https://play.google.com/store/apps/details?id=com.[redacted].android

```bash
python3 vt_recon.py -u com.[redacted].android -o results.txt
```
<img width="1756" height="928" alt="image" src="https://github.com/user-attachments/assets/709e6f5a-2dca-4e95-9b60-178522ac05b5" />

##  Disclaimer
- This script is designed to help security professionals and researchers gather intelligence on their own infrastructure
  and is intended strictly for educational and security research. 
- Users are responsible for adhering to the VirusTotal API Terms of Service.
- Please use this tool wisely. Recursive mapping generates multiple requests and can rapidly consume your VirusTotal API quota.
