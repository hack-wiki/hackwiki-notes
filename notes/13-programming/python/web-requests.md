% Filename: 13-programming/python/web-requests.md
% Display name: Web Requests & APIs
% Last update: 2026-02-11
% Authors: @TristanInSec

# Web Requests & APIs

## Overview

The requests library is the standard tool for HTTP interactions in Python,
used for API testing, web scraping, credential brute-forcing, and interacting
with web applications during security assessments. This file covers HTTP
methods, session handling, authentication, API interaction, and web scraping
with BeautifulSoup.

## HTTP Requests with requests

### Basic Requests

```python
# requests
# https://requests.readthedocs.io/

import requests

# GET request
resp = requests.get("https://httpbin.org/get")
print(resp.status_code)   # 200
print(resp.headers)        # response headers (dict-like)
print(resp.text)           # response body as string
print(resp.json())         # parse JSON response

# POST request with form data
resp = requests.post(
    "https://httpbin.org/post",
    data={"username": "admin", "password": "test"}
)

# POST request with JSON body
resp = requests.post(
    "https://httpbin.org/post",
    json={"key": "value"}
)

# PUT, DELETE, PATCH, HEAD, OPTIONS
resp = requests.put("https://httpbin.org/put", json={"updated": True})
resp = requests.delete("https://httpbin.org/delete")
resp = requests.head("https://httpbin.org/get")
resp = requests.options("https://httpbin.org/get")
```

### Custom Headers and Parameters

```python
# requests — custom headers
# https://requests.readthedocs.io/

import requests

# Custom headers (e.g., User-Agent spoofing, Authorization)
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Authorization": "Bearer eyJ0eXAi...",
    "X-Custom-Header": "value"
}
resp = requests.get("https://httpbin.org/headers", headers=headers)

# URL parameters
params = {"q": "search term", "page": 1}
resp = requests.get("https://httpbin.org/get", params=params)
# URL becomes: https://httpbin.org/get?q=search+term&page=1

# Cookies
cookies = {"session_id": "abc123", "token": "xyz789"}
resp = requests.get("https://httpbin.org/cookies", cookies=cookies)
```

### Timeouts and Error Handling

```python
# requests — timeouts and errors
# https://requests.readthedocs.io/

import requests

try:
    resp = requests.get(
        "https://httpbin.org/get",
        timeout=5,                    # seconds
        allow_redirects=True,         # follow redirects (default True)
        verify=True                   # verify TLS certificate (default True)
    )
    resp.raise_for_status()           # raise exception for 4xx/5xx

except requests.exceptions.Timeout:
    print("Request timed out")
except requests.exceptions.ConnectionError:
    print("Connection failed")
except requests.exceptions.HTTPError as e:
    print(f"HTTP error: {e.response.status_code}")
except requests.exceptions.RequestException as e:
    print(f"Request error: {e}")

# Disable TLS verification (self-signed certs in labs)
# Suppress InsecureRequestWarning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
resp = requests.get("https://10.0.0.1:8443/", verify=False)
```

## Session Handling

```python
# requests — sessions (persist cookies, headers, auth)
# https://requests.readthedocs.io/

import requests

session = requests.Session()

# Set default headers for all requests in this session
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
})

# Login (cookies are automatically stored in the session)
login_data = {"username": "admin", "password": "password123"}
resp = session.post("https://target.com/login", data=login_data)

# Subsequent requests use the session cookies
resp = session.get("https://target.com/dashboard")
print(resp.text)

# View cookies in the session
for cookie in session.cookies:
    print(f"  {cookie.name} = {cookie.value}")
```

### Authentication Types

```python
# requests — authentication
# https://requests.readthedocs.io/

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

# Basic authentication
resp = requests.get(
    "https://httpbin.org/basic-auth/user/pass",
    auth=HTTPBasicAuth("user", "pass")
)
# Shorthand:
resp = requests.get(
    "https://httpbin.org/basic-auth/user/pass",
    auth=("user", "pass")
)

# Digest authentication
resp = requests.get(
    "https://httpbin.org/digest-auth/auth/user/pass",
    auth=HTTPDigestAuth("user", "pass")
)

# Bearer token
headers = {"Authorization": "Bearer <token>"}
resp = requests.get("https://api.example.com/data", headers=headers)

# API key in header
headers = {"X-API-Key": "your-api-key-here"}
resp = requests.get("https://api.example.com/data", headers=headers)
```

## API Interaction

### REST API Patterns

```python
# requests — REST API interaction
# https://requests.readthedocs.io/

import requests
import json

base_url = "https://api.example.com/v1"

# GET — list resources
resp = requests.get(f"{base_url}/users", headers={"Authorization": "Bearer token"})
users = resp.json()

# GET — single resource
resp = requests.get(f"{base_url}/users/1")
user = resp.json()

# POST — create resource
new_user = {"name": "test", "email": "test@example.com"}
resp = requests.post(f"{base_url}/users", json=new_user)
created = resp.json()
print(f"Created user ID: {created.get('id')}")

# PUT — update resource
updates = {"name": "updated_name"}
resp = requests.put(f"{base_url}/users/1", json=updates)

# DELETE — remove resource
resp = requests.delete(f"{base_url}/users/1")
print(f"Delete status: {resp.status_code}")
```

### Pagination

```python
# requests — handle paginated APIs
# https://requests.readthedocs.io/

import requests

def get_all_pages(url, headers=None):
    """Fetch all pages from a paginated API."""
    all_results = []
    page = 1

    while True:
        resp = requests.get(url, params={"page": page}, headers=headers)
        data = resp.json()

        if not data.get("results"):
            break

        all_results.extend(data["results"])
        page += 1

        # Respect rate limits
        if resp.headers.get("X-RateLimit-Remaining") == "0":
            import time
            time.sleep(int(resp.headers.get("X-RateLimit-Reset", 60)))

    return all_results
```

## File Downloads and Uploads

```python
# requests — file operations
# https://requests.readthedocs.io/

import requests

# Download a file (streaming for large files)
def download_file(url, output_path):
    """Download a file with streaming."""
    with requests.get(url, stream=True) as resp:
        resp.raise_for_status()
        with open(output_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
    print(f"Downloaded: {output_path}")

# Upload a file
with open("payload.txt", "rb") as f:
    resp = requests.post(
        "https://target.com/upload",
        files={"file": ("payload.txt", f, "text/plain")}
    )

# Upload with additional form data
with open("shell.php", "rb") as f:
    resp = requests.post(
        "https://target.com/upload",
        files={"file": f},
        data={"description": "test upload"}
    )
```

## Web Scraping

```python
# BeautifulSoup (beautifulsoup4)
# https://www.crummy.com/software/BeautifulSoup/

from bs4 import BeautifulSoup
import requests

# Fetch and parse HTML
resp = requests.get("https://example.com")
soup = BeautifulSoup(resp.text, "html.parser")

# Find elements
title = soup.title.string
print(f"Page title: {title}")

# Extract all links
for link in soup.find_all("a", href=True):
    print(f"  {link['href']}")

# Find by CSS class
for div in soup.find_all("div", class_="content"):
    print(div.get_text())

# Find by ID
element = soup.find(id="main")

# Extract form fields (useful for CSRF token extraction)
form = soup.find("form")
if form:
    for inp in form.find_all("input"):
        name = inp.get("name", "")
        value = inp.get("value", "")
        print(f"  {name} = {value}")

# Extract all URLs from a page
def extract_urls(html, base_url):
    """Extract all unique URLs from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for tag in soup.find_all(["a", "link", "script", "img"]):
        url = tag.get("href") or tag.get("src")
        if url:
            if url.startswith("/"):
                url = base_url.rstrip("/") + url
            if url.startswith("http"):
                urls.add(url)
    return urls
```

## Proxy and TLS Configuration

```python
# requests — proxy and TLS settings
# https://requests.readthedocs.io/

import requests

# Route traffic through Burp Suite proxy
proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
resp = requests.get(
    "https://target.com",
    proxies=proxies,
    verify=False    # needed for Burp's self-signed cert
)

# Route through SOCKS proxy (requires pip install requests[socks])
socks_proxies = {
    "http": "socks5://127.0.0.1:1080",
    "https": "socks5://127.0.0.1:1080"
}

# Client certificate authentication
resp = requests.get(
    "https://target.com",
    cert=("/path/to/client.cert", "/path/to/client.key")
)
```

## References

### Tools

- [requests](https://requests.readthedocs.io/)
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)

### Further Reading

- [requests Quickstart](https://requests.readthedocs.io/en/latest/user/quickstart/)
- [Python urllib HOWTO](https://docs.python.org/3/howto/urllib2.html)
