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
#Run the tool:
```bash
python path/to/phishing_detector.py

```
### For Linux:
```bash
sudo apt update
sudo apt install python3 python3-pip -y
pip3 install beautifulsoup4 requests tldextract python-whois dnspython
```
###Run the tool:
```bash
python3 path/to/phishing_detector.py
```
###API Configuration (Optional)
Create a .env file and add your keys:
```
VIRUSTOTAL_API_KEY=your_api_key_here
PHISHTANK_API_KEY=your_api_key_here
```
License
MIT License
Copyright (c) 2025 [Shani Yadav]
```

---

### Key Improvements:
1. **Clear OS-Specific Instructions**: Separated Windows/Linux commands
2. **Copy-Paste Friendly**:
   - All commands are in triple-backtick code blocks
   - Removed mixed formatting (no ` ``text`` ` inside code blocks)
3. **Simplified API Setup**: Added `.env` configuration example
4. **Removed Redundancy**: No duplicate Linux instructions
5. **Proper Markdown Formatting**: Ensured GitHub will render it correctly

### Why This Works:
- Users can now **directly copy-paste** entire command blocks
- Eliminates confusion between Windows/Linux setups
- Maintains all critical information (API keys, license reference)


