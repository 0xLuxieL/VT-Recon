
<img width="484" height="244" alt="VT_Recon" src="https://github.com/user-attachments/assets/d84612a2-8b33-42b7-8e07-5950a5f0bc5e" />

----
This tool recursively maps target URLs and associated subdomains via the VirusTotal API, systematically discovering:
1. **Domain Lookup** (Initial Query) The script first queries the VirusTotal API's domain/report endpoint for the target domain (or a domain popped from the queue).
2. **Data Extraction and Categorization** (URLs & Domains) The JSON response from VirusTotal is parsed to extract two main categories:

      **URLs Found**:
      - `detected_urls`: URLs flagged by security vendors
      - `undetected_urls`: URLs with no detections
   
      **Domain Relationships** (New Domains for Recursion):
      - `subdomains`: Directly linked subdomains of the current domain.
      - `domain_siblings`: Related domains that share historical infrastructure


3. **Recursion and De-duplication** After extraction, the tool performs the following actions:
   
      - Saves all unique URLs found to the output file (results.txt).
      - Queues the new domains gathered (subdomains and domain_siblings) for processing.
      - It maintains a history of scanned domains to prevent duplicate processing and ensure efficient enumeration.

4. **Repeat the Process** The script then pulls the next domain from the queue and repeats the entire cycle (Steps 1–3) until the queue is empty or the process is stopped.

------   
- It supports both Public and Premium keys. Please refer to the official documentation on [Public vs. Premium API limits](https://docs.virustotal.com/reference/public-vs-premium-api) to understand your quota.
- API key rotation cycle when a key fails (Rate Limited / HTTP error)
- Triggers a `65s` cooldown if all API keys hit the standard 4 requests/minute rate limit
- Optionally, you can you can press `Enter` to pause / resume while running the script.
<img width="411" height="29" alt="pause" src="https://github.com/user-attachments/assets/1456b238-a27e-49ce-b0ae-84b6d3daa03b" />
<img width="747" height="33" alt="q" src="https://github.com/user-attachments/assets/9b1b6cf0-dbc5-46e4-bacd-67c389982b3e" />




##  Requirements

1.  **Install dependencies:**

    ```bash
    pip3 install requests
    ```

## Set up your VirusTotal API keys:
```bash
export VT_API_KEYS="your_key1,your_key2,your_key3"
```
- you can add more API keys for better performance

## Usage

```bash
python3 vt_recon.py -u example.com
```

### Custom Output File

By default, results are saved to `results.txt`. You can change this with `-o`.

```bash
python3 vt_recon.py -u example.com -o my_scan.txt
```

The tool uses a verbose logging system to show exactly what is happening:

  * **[LOOP]:** Indicates a domain has been popped from the queue for processing.
  * **[FETCHING]:** Shows the HTTP request being made and the API key fragment used.
  * **[PARSING]:** JSON analysis and extraction of intelligence.
  * **[QUEUEING]:** New subdomains/siblings found and added to the recursion loop.
  * **[URL]:** A unique URL found and saved.

**Example Output:**

```text
[INFO] Target: example.com | Keys: 3 | Output: results.txt
[INFO] Press ENTER to pause

[LOOP] Popped: example.com | Remaining: 0
  -> [FETCHING] example.com (Key: ..abc123)
  -> [PARSING] analyzing JSON response...
     L Extracted: 15 URLs and 8 Domains
     L [URL] http://sub.example.com/page1
     L [URL] http://sub.example.com/page2
     L [QUEUEING] Adding: sub1.example.com
     L [QUEUEING] Adding: sub2.example.com

[LOOP] Popped: sub1.example.com | Remaining: 1
  -> [FETCHING] sub1.example.com (Key: ..def456)
```

https://github.com/user-attachments/assets/a814f6a3-7e07-4099-a9c0-a8aa19b400e5


## ⚠️ Disclaimer

- This script is designed to help security professionals and researchers gather intelligence on their own infrastructure
  and is intended strictly for educational and security research. 
- Users are responsible for adhering to the VirusTotal API Terms of Service.
- Please use this tool wisely. Recursive mapping generates multiple requests and can rapidly consume your VirusTotal API quota.
