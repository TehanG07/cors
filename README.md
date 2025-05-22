# CORS (CROSS-ORIGIN RESOURCE SHARING)

This tool scans a list of URLs to detect CORS (Cross-Origin Resource Sharing) misconfigurations. It checks if the target websites:
Allow all origins (*) — known as wildcard CORS, which is risky.
Reflect the Origin header back in Access-Control-Allow-Origin.
Allow credentials (Access-Control-Allow-Credentials: true) along with permissive origins.
Handle CORS headers correctly in requests and responses.
It also filters out static files like CSS, JS, images, and only reports URLs that are vulnerable. The tool detects internal and external redirects and highlights potential issues.

## How to Use

1. Prepare a text file with target URLs (e.g. `urls.txt`).
2. Run the script and provide the file path when prompted.
3. Wait for the scan to finish.
4. Vulnerable URLs will be saved in `cors.txt`.

# Run the script:
./cors_detector.sh

## Output Example

| Status             | URL                                      | Details                          |
|--------------------|------------------------------------------|---------------------------------|
| 🔴 Vulnerable      | http://example.com                        | Wildcard CORS Allowed: *         |
| 🟡 Redirect        | http://redirect.com → http://finaldest.com| External redirection detected    |
| 🟢 Live            | http://liveurl.com                        | No CORS issues detected          |
| ⚫ Dead            | http://deadurl.com                        | Host unreachable or 4xx/5xx code |
