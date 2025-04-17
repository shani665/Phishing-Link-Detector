# Phishing Link Detection Tool

A Python-based tool to detect phishing URLs using domain analysis, WHOIS lookup, and HTML inspection.

## Requirements

### For Windows:
```bash
pip install requests
python -m pip install requests
pip install tldextract whois beautifulsoup4 dnspython
pip3 install --upgrade python-whois

```
### For Linux:
```bash
sudo apt update
sudo apt install python3 python3-pip -y
pip3 install beautifulsoup4 requests tldextract python-whois dnspython
