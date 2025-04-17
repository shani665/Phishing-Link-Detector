import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import webbrowser
import requests
import time
import threading
import random
import string
from urllib.parse import urlparse, quote_plus
import tldextract
import re
import socket
import ssl
import whois
from bs4 import BeautifulSoup
import dns.resolver
import datetime as dt
from collections import deque
import csv
import os
import http.server
import socketserver
import threading

# API Keys (Replace with your own)
VIRUSTOTAL_API_KEY = "Replace_with_your_own_VIRUSTOTAL_API_KEY"
GOOGLE_SAFE_BROWSING_API_KEY = "Replace_with_your_own_GOOGLE_SAFE_BROWSING_API_KEY"
IPQS_API_KEY = "Replace_with_your_own_IPQS_API_KEY"

class PhishingToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishGuard Pro - Phishing Detection & Analysis Tool")
        self.root.geometry("1200x900")
        self.root.minsize(1000, 800)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background='#f5f5f5')
        self.style.configure('TFrame', background='#f5f5f5')
        self.style.configure('TLabel', background='#f5f5f5', font=('Segoe UI', 10))
        self.style.configure('TButton', font=('Segoe UI', 10), padding=5)
        self.style.configure('Title.TLabel', font=('Segoe UI', 14, 'bold'))
        self.style.configure('Accent.TButton', background='#4a6fa5', foreground='white')
        self.style.configure('Danger.TButton', background='#c62828', foreground='white')
        self.style.map('Accent.TButton', background=[('active', '#3a5a80')])
        
        # Scan history
        self.scan_history = deque(maxlen=5)
        
        # Local server variables
        self.local_server = None
        self.server_thread = None
        self.server_port = 8080
        
        # Main container with notebook
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_scanner_tab()
        self.create_generator_tab()
        self.create_history_tab()
        
        # Status bar
        self.status_frame = ttk.Frame(root)
        self.status_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(
            self.status_frame, 
            textvariable=self.status_var, 
            relief=tk.SUNKEN,
            padding=5,
            anchor=tk.W
        )
        self.status_bar.pack(fill=tk.X)
        
        # Configure tags for colored text
        self.configure_text_tags()
        
        # Initialize scan variables
        self.scan_queue = []
        self.currently_scanning = False
        self.scan_count = 0
        self.stop_requested = False
        self.scan_start_time = None
        self.scan_results = []
        
    def configure_text_tags(self):
        """Configure text tags for colored output"""
        tags = {
            'safe': {'foreground': '#2e7d32'},
            'warning': {'foreground': '#ff8f00'},
            'danger': {'foreground': '#c62828'},
            'info': {'foreground': '#1565c0'},
            'bold': {'font': ('Consolas', 10, 'bold')},
            'url': {'foreground': '#1a237e', 'underline': 1},
            'header': {'font': ('Consolas', 11, 'bold'), 'foreground': '#333333'},
            'highlight': {'background': '#fff9c4'},
            'error': {'foreground': '#b71c1c'},
            'score_safe': {'foreground': '#2e7d32', 'font': ('Consolas', 10, 'bold')},
            'score_caution': {'foreground': '#ff8f00', 'font': ('Consolas', 10, 'bold')},
            'score_suspicious': {'foreground': '#d35400', 'font': ('Consolas', 10, 'bold')},
            'score_danger': {'foreground': '#c62828', 'font': ('Consolas', 10, 'bold')}
        }
        
        for widget_name in ['results_text', 'history_text']:
            if hasattr(self, widget_name):
                widget = getattr(self, widget_name)
                for tag, config in tags.items():
                    widget.tag_config(tag, **config)
        
        # Bind URL click event
        if hasattr(self, 'results_text'):
            self.results_text.tag_bind('url', '<Button-1>', self.open_url)
        if hasattr(self, 'history_text'):
            self.history_text.tag_bind('url', '<Button-1>', self.open_url)
    
    def create_scanner_tab(self):
        """Create the URL scanner tab"""
        self.scanner_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_tab, text="URL Scanner")
        
        # Title frame
        title_frame = ttk.Frame(self.scanner_tab)
        title_frame.pack(fill=tk.X, pady=(0, 15))
        
        title_label = ttk.Label(
            title_frame, 
            text="Phishing URL Scanner", 
            style='Title.TLabel'
        )
        title_label.pack(side=tk.LEFT)
        
        # URL input section
        input_frame = ttk.LabelFrame(
            self.scanner_tab, 
            text="URL Input", 
            padding="10"
        )
        input_frame.pack(fill=tk.X, pady=5)
        
        url_label = ttk.Label(
            input_frame, 
            text="Enter URLs (one per line or comma/space separated):"
        )
        url_label.pack(anchor=tk.W)
        
        self.url_text = scrolledtext.ScrolledText(
            input_frame, 
            height=6, 
            width=100, 
            wrap=tk.WORD, 
            font=('Consolas', 10),
            padx=5,
            pady=5
        )
        self.url_text.pack(fill=tk.X, pady=5)
        
        # Button frame
        button_frame = ttk.Frame(self.scanner_tab)
        button_frame.pack(fill=tk.X, pady=10)
        
        # Scan button with progress indicator
        scan_button_frame = ttk.Frame(button_frame)
        scan_button_frame.pack(side=tk.LEFT, padx=5)
        
        self.scan_button = ttk.Button(
            scan_button_frame, 
            text="▶ Scan URL(s)", 
            command=self.start_scan_thread, 
            style='Accent.TButton',
            width=15
        )
        self.scan_button.pack(side=tk.LEFT)
        
        # Scan time progress indicator
        self.scan_time_var = tk.StringVar()
        self.scan_time_var.set("")
        scan_time_label = ttk.Label(
            scan_button_frame, 
            textvariable=self.scan_time_var,
            font=('Segoe UI', 9),
            foreground='#555555'
        )
        scan_time_label.pack(side=tk.LEFT, padx=5)
        
        # Other buttons
        self.csv_button = ttk.Button(
            button_frame, 
            text="📂 Upload CSV", 
            command=self.upload_csv,
            width=12
        )
        self.csv_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(
            button_frame, 
            text="⏹ Stop Scan", 
            command=self.stop_scan,
            state='disabled',
            width=12
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Report buttons frame
        report_buttons_frame = ttk.Frame(button_frame)
        report_buttons_frame.pack(side=tk.RIGHT, padx=5)
        
        self.full_report_button = ttk.Button(
            report_buttons_frame, 
            text="📄 Full Report", 
            command=self.show_full_report,
            state='disabled',
            width=12
        )
        self.full_report_button.pack(side=tk.LEFT, padx=5)
        
        self.download_button = ttk.Button(
            report_buttons_frame, 
            text="💾 Save Report", 
            command=self.save_report,
            state='disabled',
            width=12
        )
        self.download_button.pack(side=tk.LEFT)
        
        self.clear_button = ttk.Button(
            button_frame, 
            text="🗑 Clear", 
            command=self.clear_results,
            width=12
        )
        self.clear_button.pack(side=tk.RIGHT, padx=5)
        
        # Progress bar
        progress_frame = ttk.Frame(self.scanner_tab)
        progress_frame.pack(fill=tk.X, pady=5)
        
        progress_label = ttk.Label(progress_frame, text="Progress:")
        progress_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.progress = ttk.Progressbar(
            progress_frame, 
            orient=tk.HORIZONTAL, 
            mode='determinate'
        )
        self.progress.pack(fill=tk.X, expand=True)
        
        # Results section
        results_frame = ttk.Frame(self.scanner_tab)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(
            results_frame, 
            height=25, 
            width=100, 
            wrap=tk.WORD, 
            font=('Consolas', 10),
            padx=5,
            pady=5,
            state='normal'
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
    
    def create_generator_tab(self):
        """Create the phishing link generator tab (for educational purposes)"""
        self.generator_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.generator_tab, text="Link Generator")
        
        # Disclaimer
        disclaimer_frame = ttk.Frame(self.generator_tab)
        disclaimer_frame.pack(fill=tk.X, pady=(0, 15))
        
        disclaimer = ttk.Label(
            disclaimer_frame,
            text="⚠️ WARNING: This tool is for educational and security testing purposes only. \n"
                 "Generating phishing links for malicious purposes is illegal.",
            foreground='red',
            font=('Segoe UI', 9, 'bold'),
            justify=tk.CENTER
        )
        disclaimer.pack(fill=tk.X, pady=5)
        
        # Generator controls
        gen_frame = ttk.LabelFrame(
            self.generator_tab,
            text="Phishing Link Generator",
            padding=10
        )
        gen_frame.pack(fill=tk.X, pady=5)
        
        # Target URL
        ttk.Label(gen_frame, text="Legitimate Site URL:").grid(row=0, column=0, sticky=tk.W)
        self.legit_url = ttk.Entry(gen_frame, width=50)
        self.legit_url.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Phishing Domain
        ttk.Label(gen_frame, text="Phishing Domain (leave blank for localhost):").grid(row=1, column=0, sticky=tk.W)
        self.phish_domain = ttk.Entry(gen_frame, width=50)
        self.phish_domain.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # URL Path
        ttk.Label(gen_frame, text="URL Path:").grid(row=2, column=0, sticky=tk.W)
        self.url_path = ttk.Entry(gen_frame, width=50)
        self.url_path.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Obfuscation level
        ttk.Label(gen_frame, text="Obfuscation Level:").grid(row=3, column=0, sticky=tk.W)
        self.obfuscation = ttk.Combobox(
            gen_frame, 
            values=["None", "Low", "Medium", "High"], 
            state="readonly",
            width=47
        )
        self.obfuscation.current(0)
        self.obfuscation.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Generate button
        gen_button = ttk.Button(
            gen_frame,
            text="Generate Phishing URL",
            command=self.generate_phishing_url,
            style='Danger.TButton'
        )
        gen_button.grid(row=4, column=1, pady=10, sticky=tk.E)
        
        # Generated URL display
        result_frame = ttk.LabelFrame(
            self.generator_tab,
            text="Generated URL",
            padding=10
        )
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.generated_url = tk.Text(
            result_frame,
            height=3,
            wrap=tk.WORD,
            font=('Consolas', 10),
            padx=5,
            pady=5
        )
        self.generated_url.pack(fill=tk.X, pady=5)
        
        # Server controls
        server_frame = ttk.Frame(result_frame)
        server_frame.pack(fill=tk.X, pady=5)
        
        self.start_server_button = ttk.Button(
            server_frame,
            text="Start Local Server",
            command=self.start_local_server,
            state='normal'
        )
        self.start_server_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_server_button = ttk.Button(
            server_frame,
            text="Stop Local Server",
            command=self.stop_local_server,
            state='disabled'
        )
        self.stop_server_button.pack(side=tk.LEFT, padx=5)
        
        self.server_status = ttk.Label(
            server_frame,
            text="Server: Stopped",
            foreground='red'
        )
        self.server_status.pack(side=tk.LEFT, padx=5)
        
        # Test button
        test_button = ttk.Button(
            result_frame,
            text="Test URL in Browser",
            command=self.test_generated_url
        )
        test_button.pack(pady=5)
        
        # Analysis button
        analyze_button = ttk.Button(
            result_frame,
            text="Analyze Generated URL",
            command=self.analyze_generated_url
        )
        analyze_button.pack(pady=5)
        
        # Make columns resizable
        gen_frame.columnconfigure(1, weight=1)
    
    def create_history_tab(self):
        """Create the scan history tab"""
        self.history_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.history_tab, text="Scan History")
        
        # History text area
        self.history_text = scrolledtext.ScrolledText(
            self.history_tab,
            wrap=tk.WORD,
            font=('Consolas', 10),
            padx=5,
            pady=5,
            state='disabled'
        )
        self.history_text.pack(fill=tk.BOTH, expand=True)
        
        # Clear history button
        clear_history_button = ttk.Button(
            self.history_tab,
            text="Clear History",
            command=self.clear_history
        )
        clear_history_button.pack(pady=10)
    
    def generate_phishing_url(self):
        """Generate a phishing URL based on user input"""
        legit_url = self.legit_url.get().strip()
        phish_domain = self.phish_domain.get().strip()
        path = self.url_path.get().strip()
        obf_level = self.obfuscation.get()
        
        if not legit_url:
            messagebox.showerror("Error", "Please enter a legitimate URL")
            return
        
        # If no phishing domain is provided, use localhost
        if not phish_domain:
            phish_domain = "localhost"
        
        # Generate the base phishing URL
        if path:
            base_url = f"http://{phish_domain}:{self.server_port}/{path.lstrip('/')}"
        else:
            base_url = f"http://{phish_domain}:{self.server_port}"
        
        # Apply obfuscation
        if obf_level == "Low":
            # Add random subdomain
            rand_str = ''.join(random.choices(string.ascii_lowercase, k=5))
            base_url = base_url.replace(f"://{phish_domain}", f"://{rand_str}.{phish_domain}")
        elif obf_level == "Medium":
            # Add URL encoding
            base_url = base_url.replace("://", "://%77%77%77%2E")  # "www."
            base_url = base_url.replace(".", "%2E")
        elif obf_level == "High":
            # Use IP address and port
            try:
                if phish_domain != "localhost":
                    ip = socket.gethostbyname(phish_domain)
                    base_url = base_url.replace(f"://{phish_domain}", f"://{ip}:8080")
            except:
                pass
        
        # Add the legitimate URL as a parameter
        encoded_url = quote_plus(legit_url)
        final_url = f"{base_url}?redirect={encoded_url}"
        
        # Display the generated URL
        self.generated_url.config(state='normal')
        self.generated_url.delete('1.0', tk.END)
        self.generated_url.insert('1.0', final_url)
        self.generated_url.config(state='disabled')
        
        self.update_status("Phishing URL generated")
    
    def start_local_server(self):
        """Start a local HTTP server for testing phishing pages"""
        if self.local_server is not None:
            return
            
        class PhishingRequestHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                # Serve a simple phishing page
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                
                # Get the redirect URL from query parameters
                query = urlparse(self.path).query
                query_components = dict(qc.split("=") for qc in query.split("&") if "=" in qc)
                redirect_url = query_components.get("redirect", "https://example.com")
                
                # Create a simple phishing page
                phishing_page = f"""
                <html>
                <head><title>Login Required</title></head>
                <body>
                    <h1>Your Account Requires Verification</h1>
                    <p>Please login to continue:</p>
                    <form action="{redirect_url}" method="post">
                        Username: <input type="text" name="username"><br>
                        Password: <input type="password" name="password"><br>
                        <input type="submit" value="Login">
                    </form>
                </body>
                </html>
                """
                
                self.wfile.write(phishing_page.encode())
        
        try:
            # Try to find an available port
            for port in range(self.server_port, self.server_port + 10):
                try:
                    self.local_server = socketserver.TCPServer(("", port), PhishingRequestHandler)
                    self.server_port = port
                    break
                except OSError:
                    continue
            
            if self.local_server is None:
                messagebox.showerror("Error", "Could not start server - no available ports")
                return
                
            self.server_thread = threading.Thread(target=self.local_server.serve_forever, daemon=True)
            self.server_thread.start()
            
            self.start_server_button["state"] = "disabled"
            self.stop_server_button["state"] = "normal"
            self.server_status.config(text=f"Server: Running on port {self.server_port}", foreground='green')
            
            self.update_status(f"Local server started on port {self.server_port}")
        except Exception as e:
            messagebox.showerror("Server Error", f"Failed to start server: {str(e)}")
    
    def stop_local_server(self):
        """Stop the local HTTP server"""
        if self.local_server:
            self.local_server.shutdown()
            self.local_server.server_close()
            self.local_server = None
            self.server_thread = None
            
            self.start_server_button["state"] = "normal"
            self.stop_server_button["state"] = "disabled"
            self.server_status.config(text="Server: Stopped", foreground='red')
            
            self.update_status("Local server stopped")
    
    def test_generated_url(self):
        """Open the generated URL in default browser"""
        url = self.generated_url.get('1.0', tk.END).strip()
        if url:
            webbrowser.open_new_tab(url)
        else:
            messagebox.showwarning("Warning", "No URL to test")
    
    def analyze_generated_url(self):
        """Analyze the generated phishing URL"""
        url = self.generated_url.get('1.0', tk.END).strip()
        if not url:
            messagebox.showwarning("Warning", "No URL to analyze")
            return
        
        # Switch to scanner tab
        self.notebook.select(self.scanner_tab)
        
        # Set the URL in the scanner
        self.url_text.delete('1.0', tk.END)
        self.url_text.insert('1.0', url)
        
        # Start the scan
        self.start_scan_thread()
    
    def start_scan_thread(self):
        """Start scanning in a separate thread to keep UI responsive"""
        if self.currently_scanning:
            return
            
        raw_input = self.url_text.get("1.0", tk.END).strip()
        if not raw_input:
            messagebox.showwarning("Input Error", "Please enter at least one URL to scan.")
            return
            
        # Split on spaces, commas, or newlines
        urls = re.split(r'[\s,]+', raw_input)
        urls = [url.strip() for url in urls if url.strip()]
        
        if not urls:
            messagebox.showwarning("Input Error", "No valid URLs found in input.")
            return
            
        self.scan_queue = urls
        self.scan_count = len(urls)
        self.currently_scanning = True
        self.stop_requested = False
        self.progress["maximum"] = len(urls)
        self.progress["value"] = 0
        self.scan_results = []
        self.scan_start_time = time.time()
        self.update_scan_time()
        
        self.clear_results()
        self.update_status(f"Scanning {len(urls)} URLs...")
        self.toggle_buttons(scanning=True)
        
        # Start scan thread
        scan_thread = threading.Thread(target=self.process_scan_queue, daemon=True)
        scan_thread.start()
    
    def process_scan_queue(self):
        """Process the scan queue in the background thread"""
        for i, url in enumerate(self.scan_queue, 1):
            if self.stop_requested:
                break
                
            self.progress["value"] = i
            self.update_status(f"Scanning URL {i} of {self.scan_count}: {url}")
            
            result = self.deep_scan_url(url)
            self.display_result(url, result)
            self.scan_results.append((url, result))
            
            # Small delay to prevent API rate limiting
            time.sleep(1)
            
        self.scan_complete()
    
    def deep_scan_url(self, url):
        """Perform a comprehensive scan of the URL"""
        report = []
        score = 50  # Initialize base score
        
        def safe_request(url):
            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                }
                return requests.get(url, headers=headers, timeout=15, allow_redirects=True)
            except Exception as e:
                return None

        # Normalize URL
        original_url = url
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        full_domain = parsed.netloc

        report.append(f"🔍 Domain: {domain}")
        report.append(f"🌐 Full domain: {full_domain}")

        # IP Address lookup
        try:
            ip = socket.gethostbyname(parsed.hostname)
            report.append(f"📂 IP Address: {ip}")
            
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                report.append(f"📡 Reverse DNS: {hostname}")
                
                # Check if it's a cloud provider
                if any(x in hostname.lower() for x in ['aws', 'amazon', 'google', 'cloudfront', 'azure']):
                    report.append("⚠️ Hosted on cloud provider (common for phishing)")
                    score += 5
            except:
                pass
        except Exception as e:
            report.append(f"⚠️ Failed to resolve IP: {str(e)}")
            score += 2

        # Enhanced WHOIS lookup with domain age calculation
        try:
            whois_info = whois.whois(full_domain)
            creation_date = whois_info.creation_date

            # Handle cases where creation_date might be a list
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                domain_age_days = (dt.datetime.now() - creation_date).days
                
                # Visual domain age indicator
                if domain_age_days < 30:
                    report.append(f"📆 Domain Age: {domain_age_days} days (Very New 🚨)")
                    score += 15
                elif domain_age_days < 180:
                    report.append(f"📆 Domain Age: {domain_age_days} days (New ⚠️)")
                    score += 5
                else:
                    report.append(f"📆 Domain Age: {domain_age_days} days (Established ✅)")
            else:
                report.append("⚠️ Domain creation date not found")
                score += 2

        except Exception as e:
            report.append(f"⚠️ WHOIS lookup failed or date error: {e}")
            score += 2

        # SSL/TLS check
        if parsed.scheme == "https":
            report.append("✅ HTTPS is used")
            score -= 10
            
            try:
                context = ssl.create_default_context()
                with socket.create_connection((parsed.hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                        cert = ssock.getpeercert()
                        report.append("🔐 SSL Certificate found")
                        score -= 5
                        
                        # Get issuer
                        issuer = dict(x[0] for x in cert['issuer'])
                        report.append(f"   Issuer: {issuer.get('organizationName', 'Unknown')}")
                        
                        # Validity dates
                        not_before = dt.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        not_after = dt.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        report.append(f"   Valid From: {not_before.strftime('%Y-%m-%d')}")
                        report.append(f"   Valid Until: {not_after.strftime('%Y-%m-%d')}")
                        
                        # Check if certificate is expired
                        if dt.datetime.now() > not_after:
                            report.append("⚠️ Certificate has expired!")
                            score += 15
                            
                        # Check if certificate is self-signed
                        if issuer.get('organizationName') == issuer.get('commonName'):
                            report.append("⚠️ Certificate may be self-signed")
                            score += 10
            except Exception as e:
                report.append(f"⚠️ SSL Certificate could not be verified: {str(e)}")
                score += 5
        else:
            report.append("⚠️ HTTPS is NOT used")
            score += 15

        # Domain analysis
        suspicious_keywords = ["login", "secure", "account", "update", "verify", "bank", "paypal", "ebay", "apple"]
        found_keywords = [kw for kw in suspicious_keywords if kw in domain.lower()]
        if found_keywords:
            report.append(f"⚠️ Suspicious keywords found in domain: {', '.join(found_keywords)}")
            score += 10

        # Typosquatting check
        for brand in ["google", "facebook", "amazon", "microsoft", "apple", "paypal", "ebay", "netflix"]:
            if brand in domain.lower() and brand not in full_domain.lower():
                report.append(f"⚠️ Typosquatting suspected on: {brand}")
                score += 20

        # DNS records check
        for record_type in ["A", "MX", "TXT", "NS"]:
            try:
                answers = dns.resolver.resolve(domain, record_type, lifetime=5.0)
                for rdata in answers:
                    report.append(f"📱 {record_type} Record: {rdata.to_text()}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers) as e:
                pass  # Don't show errors for missing records

        # URL content analysis
        response = safe_request(url)
        if response:
            if response.url != url:
                report.append(f"🔁 Redirects to: {response.url}")
                score += 5
                
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                
                # Check for login forms
                forms = soup.find_all("form")
                login_forms = [f for f in forms if any("password" in (i.get("type") or "").lower() for i in f.find_all("input"))]
                if login_forms:
                    report.append(f"🔐 {len(login_forms)} login form(s) found")
                    score += 10
                    
                # Check for suspicious JavaScript
                scripts = soup.find_all("script")
                suspicious_js = []
                for script in scripts:
                    if script.string:
                        if "eval(" in script.string or "atob(" in script.string:
                            suspicious_js.append(script)
                            
                if suspicious_js:
                    report.append("⚠️ Suspicious JavaScript functions detected (eval/atob)")
                    score += 15
                    
                # Check for hidden elements
                hidden_elements = soup.find_all(style=re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I))
                if hidden_elements:
                    report.append(f"⚠️ {len(hidden_elements)} hidden elements found")
                    score += 5
                    
                # Check for iframes
                iframes = soup.find_all("iframe")
                if iframes:
                    report.append(f"⚠️ {len(iframes)} iframe(s) found")
                    score += 5
                    
                # Check title
                title = soup.title.string if soup.title else None
                if title:
                    report.append(f"📝 Page Title: {title}")
                    
                    # Check for suspicious title keywords
                    title_keywords = ["login", "sign in", "account", "verify", "security", "update"]
                    if any(kw in title.lower() for kw in title_keywords):
                        report.append("⚠️ Suspicious keywords in page title")
                        score += 5
        else:
            report.append("⚠️ Could not fetch URL content")
            score += 5

        # API checks
        vt_result = self.virustotal_check(original_url)
        report.append(vt_result)

        gsb_result = self.google_safe_browsing_check(original_url)
        report.append(gsb_result)

        ipqs_result = self.ipqs_check(original_url)
        report.append(ipqs_result)

        # Calculate threat score
        # VirusTotal score adjustment
        vt_mal_match = re.search(r"(\d+) malicious", vt_result)
        if vt_mal_match:
            mal_count = int(vt_mal_match.group(1))
            score += mal_count * 5
            
        # Google Safe Browsing adjustment
        if "Threat detected" in gsb_result:
            score += 20
            
        # IPQS adjustment
        ipqs_risk_match = re.search(r"Risk Score: (\d+)", ipqs_result)
        if ipqs_risk_match:
            risk_score = int(ipqs_risk_match.group(1))
            score += risk_score / 2

        # Cap score between 0 and 100
        score = max(0, min(score, 100))
        
        # Determine risk level and verdict
        if score >= 80:
            risk_level = "🚨 HIGH RISK (Very likely phishing)"
            verdict = "Very Likely a Phishing Site 🚨"
        elif score >= 60:
            risk_level = "⚠️ MEDIUM RISK (Suspicious)"
            verdict = "Suspicious – Investigate Further ⚠️"
        elif score >= 30:
            risk_level = "⚠️ LOW RISK (Potentially suspicious)"
            verdict = "Low Risk – Stay Cautious"
        else:
            risk_level = "✅ LIKELY SAFE"
            verdict = "Safe ✅"
            
        report.append(f"\n🧙 Threat Score: {int(score)}/100 - {risk_level}")
        report.append(f"🧠 Verdict: {verdict}")

        return "\n".join(report)
    
    def virustotal_check(self, url):
        """Check URL with VirusTotal API"""
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        params = {"url": url}
        try:
            # Submit URL for scanning
            scan_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data=params,
                timeout=20
            )
            
            if scan_resp.status_code == 200:
                scan_data = scan_resp.json()
                if "data" in scan_data and "id" in scan_data["data"]:
                    scan_id = scan_data["data"]["id"]
                    
                    # Wait for analysis to complete (VirusTotal needs some time)
                    time.sleep(5)
                    
                    # Get analysis results
                    analysis_resp = requests.get(
                        f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                        headers=headers,
                        timeout=20
                    )
                    
                    if analysis_resp.status_code == 200:
                        analysis_data = analysis_resp.json()
                        if "data" in analysis_data and "attributes" in analysis_data["data"]:
                            stats = analysis_data["data"]["attributes"]["stats"]
                            mal_count = stats.get("malicious", 0)
                            sus_count = stats.get("suspicious", 0)
                            total = sum(stats.values())

                            # Get report link
                            if "meta" in scan_data and "url_info" in scan_data["meta"]:
                                encoded_url = scan_data["meta"]["url_info"]["id"]
                                report_link = f"https://www.virustotal.com/gui/url/{encoded_url}/detection"
                            else:
                                report_link = "Not available"

                            return (f"✅ VirusTotal: {mal_count} malicious, {sus_count} suspicious out of {total} engines\n"
                                    f"🔗 Full Report: {report_link}")
                        else:
                            return "⚠️ VirusTotal: Could not parse analysis data"
                    else:
                        return f"⚠️ VirusTotal: Analysis request failed (Status: {analysis_resp.status_code})"
                else:
                    return "⚠️ VirusTotal: Could not get scan ID from response"
            else:
                return f"⚠️ VirusTotal: Scan submission failed (Status: {scan_resp.status_code})"
        except requests.exceptions.Timeout:
            return "⚠️ VirusTotal: Request timed out"
        except Exception as e:
            return f"⚠️ VirusTotal: Error - {str(e)}"
            
    def google_safe_browsing_check(self, url):
        """Check URL with Google Safe Browsing API"""
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        body = {
            "client": {
                "clientId": "phishing-scanner",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        try:
            resp = requests.post(api_url, json=body, timeout=15)
            if resp.status_code == 200:
                matches = resp.json().get("matches")
                if matches:
                    threats = ", ".join([m['threatType'] for m in matches])
                    return f"🚩 Google Safe Browsing: Threat detected - {threats}"
                else:
                    return "✅ Google Safe Browsing: No threats found"
            else:
                return f"⚠️ Google Safe Browsing: Scan failed (Status: {resp.status_code})"
        except requests.exceptions.Timeout:
            return "⚠️ Google Safe Browsing: Request timed out"
        except Exception as e:
            return f"⚠️ Google Safe Browsing: Error - {str(e)}"
            
    def ipqs_check(self, url):
        """Check URL with IPQualityScore API"""
        try:
            encoded_url = quote_plus(url)
            full_url = f"https://ipqualityscore.com/api/json/url/{IPQS_API_KEY}/{encoded_url}"
            resp = requests.get(full_url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("unsafe"):
                    return f"🚨 IPQualityScore: URL flagged as unsafe (Phishing: {data.get('phishing', False)}, Suspicious: {data.get('suspicious', False)}, Risk Score: {data.get('risk_score', 0)})"
                else:
                    return f"✅ IPQualityScore: URL is considered safe (Risk Score: {data.get('risk_score', 0)})"
            else:
                return f"⚠️ IPQualityScore: Scan failed (Status: {resp.status_code})"
        except requests.exceptions.Timeout:
            return "⚠️ IPQualityScore: Request timed out"
        except Exception as e:
            return f"⚠️ IPQualityScore: Error - {str(e)}"
    
    def update_scan_time(self):
        """Update the scan time indicator"""
        if self.currently_scanning and self.scan_start_time:
            elapsed = time.time() - self.scan_start_time
            self.scan_time_var.set(f"Scanning: {elapsed:.1f}s")
            self.root.after(200, self.update_scan_time)
        else:
            self.scan_time_var.set("")
    
    def scan_complete(self):
        """Handle scan completion"""
        if self.stop_requested:
            self.update_status(f"Scan stopped. {self.progress['value']} of {self.scan_count} URLs processed.")
        else:
            self.update_status(f"Scan completed. {self.scan_count} URLs processed.")
            
        self.currently_scanning = False
        self.stop_requested = False
        self.toggle_buttons(scanning=False)
        
        # Enable report buttons if we have results
        if self.scan_results:
            self.full_report_button["state"] = "normal"
            self.download_button["state"] = "normal"
            
        # Add to scan history
        self.add_to_scan_history()
    
    def add_to_scan_history(self):
        """Add current scan to history"""
        if not self.scan_results:
            return
            
        self.history_text.config(state='normal')
        
        # Add separator if not first entry
        if self.scan_history:
            self.history_text.insert(tk.END, "\n" + "="*80 + "\n\n")
        
        # Add timestamp
        timestamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.history_text.insert(tk.END, f"Scan at {timestamp}\n", 'header')
        
        # Add summary of results
        for url, result in self.scan_results:
            # Extract score from result
            score_match = re.search(r"Threat Score: (\d+)/100", result)
            if score_match:
                score = int(score_match.group(1))
                if score >= 80:
                    score_tag = 'score_danger'
                elif score >= 60:
                    score_tag = 'score_suspicious'
                elif score >= 30:
                    score_tag = 'score_caution'
                else:
                    score_tag = 'score_safe'
                
                self.history_text.insert(tk.END, f"• ", 'info')
                self.history_text.insert(tk.END, f"{url} ", 'url')
                self.history_text.insert(tk.END, f"Score: {score}/100\n", score_tag)
        
        self.history_text.see(tk.END)
        self.history_text.config(state='disabled')
        
        # Add to history deque
        self.scan_history.append((timestamp, self.scan_results.copy()))
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.currently_scanning:
            self.stop_requested = True
            self.stop_button["state"] = "disabled"
            self.update_status("Stopping scan...")
            
    def toggle_buttons(self, scanning):
        """Toggle button states based on scanning status"""
        if scanning:
            self.scan_button["state"] = "disabled"
            self.csv_button["state"] = "disabled"
            self.clear_button["state"] = "disabled"
            self.stop_button["state"] = "normal"
            self.full_report_button["state"] = "disabled"
            self.download_button["state"] = "disabled"
        else:
            self.scan_button["state"] = "normal"
            self.csv_button["state"] = "normal"
            self.clear_button["state"] = "normal"
            self.stop_button["state"] = "disabled"
            
    def show_full_report(self):
        """Show a popup with the full scan report"""
        if not self.scan_results:
            return
            
        report_window = tk.Toplevel(self.root)
        report_window.title("Full Scan Report")
        report_window.geometry("900x700")
        
        report_text = scrolledtext.ScrolledText(
            report_window,
            wrap=tk.WORD,
            font=('Consolas', 10),
            padx=10,
            pady=10
        )
        report_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for the report text
        tags = {
            'safe': {'foreground': '#2e7d32'},
            'warning': {'foreground': '#ff8f00'},
            'danger': {'foreground': '#c62828'},
            'info': {'foreground': '#1565c0'},
            'bold': {'font': ('Consolas', 10, 'bold')},
            'url': {'foreground': '#1a237e', 'underline': 1},
            'header': {'font': ('Consolas', 11, 'bold'), 'foreground': '#333333'},
            'highlight': {'background': '#fff9c4'},
            'error': {'foreground': '#b71c1c'},
            'score_safe': {'foreground': '#2e7d32', 'font': ('Consolas', 10, 'bold')},
            'score_caution': {'foreground': '#ff8f00', 'font': ('Consolas', 10, 'bold')},
            'score_suspicious': {'foreground': '#d35400', 'font': ('Consolas', 10, 'bold')},
            'score_danger': {'foreground': '#c62828', 'font': ('Consolas', 10, 'bold')}
        }
        
        for tag, config in tags.items():
            report_text.tag_config(tag, **config)
        
        # Insert all scan results
        for url, result in self.scan_results:
            report_text.insert(tk.END, f"Scan Results for: ", 'header')
            report_text.insert(tk.END, f"{url}\n", ('header', 'url'))
            report_text.insert(tk.END, f"{'-'*80}\n", 'header')
            
            for line in result.split("\n"):
                if not line.strip():
                    continue
                    
                if line.startswith("✅"):
                    report_text.insert(tk.END, "✓ ", 'safe')
                    report_text.insert(tk.END, line[2:] + "\n", 'safe')
                elif line.startswith("⚠️"):
                    report_text.insert(tk.END, "⚠ ", 'warning')
                    report_text.insert(tk.END, line[2:] + "\n", 'warning')
                elif line.startswith("🚩"):
                    report_text.insert(tk.END, "‼ ", 'danger')
                    report_text.insert(tk.END, line[2:] + "\n", 'danger')
                elif line.startswith("🚨"):
                    report_text.insert(tk.END, "☠ ", 'danger')
                    report_text.insert(tk.END, line[2:] + "\n", 'danger')
                elif line.startswith("🔍") or line.startswith("🌐"):
                    report_text.insert(tk.END, "• ", 'info')
                    report_text.insert(tk.END, line[2:] + "\n", 'info')
                elif line.startswith("📂") or line.startswith("📡") or line.startswith("🏢"):
                    report_text.insert(tk.END, "• ", 'info')
                    report_text.insert(tk.END, line[2:] + "\n", 'info')
                elif line.startswith("📅") or line.startswith("🔐"):
                    report_text.insert(tk.END, "• ", 'info')
                    report_text.insert(tk.END, line[2:] + "\n", 'info')
                elif line.startswith("📱"):
                    report_text.insert(tk.END, "• ", 'info')
                    report_text.insert(tk.END, line[2:] + "\n", 'info')
                elif line.startswith("📝"):
                    report_text.insert(tk.END, "• ", 'info')
                    report_text.insert(tk.END, line[2:] + "\n", 'info')
                elif line.startswith("🔁"):
                    report_text.insert(tk.END, "↪ ", 'warning')
                    report_text.insert(tk.END, line[2:] + "\n", 'warning')
                elif line.startswith("🧙"):
                    score_match = re.search(r"(\d+)/100", line)
                    if score_match:
                        score = int(score_match.group(1))
                        if score >= 80:
                            tag = 'score_danger'
                        elif score >= 60:
                            tag = 'score_suspicious'
                        elif score >= 30:
                            tag = 'score_caution'
                        else:
                            tag = 'score_safe'
                            
                        parts = line.split(":")
                        report_text.insert(tk.END, parts[0] + ":", 'bold')
                        report_text.insert(tk.END, parts[1] + "\n\n", tag)
                elif "error" in line.lower() or "failed" in line.lower():
                    report_text.insert(tk.END, "✗ ", 'error')
                    report_text.insert(tk.END, line + "\n", 'error')
                else:
                    report_text.insert(tk.END, line + "\n")
                    
            report_text.insert(tk.END, "\n")
            
        report_text.config(state='disabled')
        
        # Add close button
        close_button = ttk.Button(
            report_window,
            text="Close",
            command=report_window.destroy
        )
        close_button.pack(pady=10)
    
    def save_report(self):
        """Save the scan report to a file"""
        if not self.scan_results:
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Scan Report"
        )
        
        if not file_path:
            return
            
        try:
            if file_path.endswith('.csv'):
                self.save_as_csv(file_path)
            else:
                self.save_as_text(file_path)
                
            messagebox.showinfo("Report Saved", f"Scan report saved successfully to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save report: {str(e)}")
    
    def save_as_csv(self, file_path):
        """Save report in CSV format"""
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "Threat Score", "Verdict", "Details"])
            
            for url, result in self.scan_results:
                # Extract score and verdict
                score_match = re.search(r"Threat Score: (\d+)/100", result)
                verdict_match = re.search(r"Verdict: (.+)", result)
                
                score = score_match.group(1) if score_match else "N/A"
                verdict = verdict_match.group(1) if verdict_match else "N/A"
                
                # Clean up details
                details = "\n".join([line for line in result.split("\n") 
                                   if not line.startswith("🧙") and 
                                   not line.startswith("Scan Results for:") and
                                   not line.startswith("------")])
                
                writer.writerow([url, score, verdict, details])
    
    def save_as_text(self, file_path):
        """Save report in text format"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("Phishing Scan Report\n")
            f.write(f"Generated on: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*50 + "\n\n")
            
            for url, result in self.scan_results:
                f.write(f"Scan Results for: {url}\n")
                f.write("-"*80 + "\n")
                f.write(result + "\n\n")
                
            # Add score guide
            f.write("\n📘 Threat Score Guide:\n")
            f.write("- 0–30   ✅ Safe\n")
            f.write("- 31–60  ⚠️ Caution\n")
            f.write("- 61–80  ❗ Suspicious\n")
            f.write("- 81–100 🚨 Dangerous\n")
    
    def upload_csv(self):
        """Upload and scan URLs from a CSV file"""
        if self.currently_scanning:
            messagebox.showwarning("Scan in Progress", "Please wait for current scan to complete.")
            return
            
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return
            
        try:
            with open(file_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                urls = []
                for row in reader:
                    if row and row[0].strip():
                        urls.append(row[0].strip())
                        
                if not urls:
                    messagebox.showwarning("CSV Error", "No URLs found in the CSV file.")
                    return
                    
                self.url_text.delete("1.0", tk.END)
                self.url_text.insert(tk.END, "\n".join(urls))
                self.start_scan_thread()
                
        except Exception as e:
            messagebox.showerror("CSV Error", f"Error reading CSV file: {str(e)}")
            
    def clear_results(self):
        """Clear the results text area"""
        if self.currently_scanning:
            messagebox.showwarning("Scan in Progress", "Cannot clear results during scan.")
            return
            
        self.results_text.config(state='normal')
        self.results_text.delete("1.0", tk.END)
        self.results_text.config(state='normal')
        self.progress["value"] = 0
        self.update_status("Ready to scan")
        self.scan_results = []
        self.full_report_button["state"] = "disabled"
        self.download_button["state"] = "disabled"
    
    def clear_history(self):
        """Clear the scan history"""
        self.history_text.config(state='normal')
        self.history_text.delete("1.0", tk.END)
        self.history_text.config(state='disabled')
        self.scan_history.clear()
        self.update_status("Scan history cleared")
        
    def update_status(self, message):
        """Update the status bar"""
        self.status_var.set(message)
        self.root.update_idletasks()
        
    def display_result(self, url, result):
        """Display the scan result with formatted text"""
        self.results_text.config(state='normal')
        
        # Insert URL header
        self.results_text.insert(tk.END, f"Scan Results for: ", 'header')
        self.results_text.insert(tk.END, f"{url}\n", ('header', 'url'))
        self.results_text.insert(tk.END, f"{'-'*80}\n", 'header')
        
        # Process each line of the result
        for line in result.split("\n"):
            if not line.strip():
                continue
                
            if line.startswith("✅"):
                self.results_text.insert(tk.END, "✓ ", 'safe')
                self.results_text.insert(tk.END, line[2:] + "\n", 'safe')
            elif line.startswith("⚠️"):
                self.results_text.insert(tk.END, "⚠ ", 'warning')
                self.results_text.insert(tk.END, line[2:] + "\n", 'warning')
            elif line.startswith("🚩"):
                self.results_text.insert(tk.END, "‼ ", 'danger')
                self.results_text.insert(tk.END, line[2:] + "\n", 'danger')
            elif line.startswith("🚨"):
                self.results_text.insert(tk.END, "☠ ", 'danger')
                self.results_text.insert(tk.END, line[2:] + "\n", 'danger')
            elif line.startswith("🔍") or line.startswith("🌐"):
                self.results_text.insert(tk.END, "• ", 'info')
                self.results_text.insert(tk.END, line[2:] + "\n", 'info')
            elif line.startswith("📂") or line.startswith("📡") or line.startswith("🏢"):
                self.results_text.insert(tk.END, "• ", 'info')
                self.results_text.insert(tk.END, line[2:] + "\n", 'info')
            elif line.startswith("📅") or line.startswith("🔐"):
                self.results_text.insert(tk.END, "• ", 'info')
                self.results_text.insert(tk.END, line[2:] + "\n", 'info')
            elif line.startswith("📱"):
                self.results_text.insert(tk.END, "• ", 'info')
                self.results_text.insert(tk.END, line[2:] + "\n", 'info')
            elif line.startswith("📝"):
                self.results_text.insert(tk.END, "• ", 'info')
                self.results_text.insert(tk.END, line[2:] + "\n", 'info')
            elif line.startswith("🔁"):
                self.results_text.insert(tk.END, "↪ ", 'warning')
                self.results_text.insert(tk.END, line[2:] + "\n", 'warning')
            elif line.startswith("🧙"):
                # Highlight the threat score
                score_match = re.search(r"(\d+)/100", line)
                if score_match:
                    score = int(score_match.group(1))
                    if score >= 80:
                        tag = 'score_danger'
                    elif score >= 60:
                        tag = 'score_suspicious'
                    elif score >= 30:
                        tag = 'score_caution'
                    else:
                        tag = 'score_safe'
                        
                    parts = line.split(":")
                    self.results_text.insert(tk.END, parts[0] + ":", 'bold')
                    self.results_text.insert(tk.END, parts[1] + "\n\n", tag)
            elif "error" in line.lower() or "failed" in line.lower():
                self.results_text.insert(tk.END, "✗ ", 'error')
                self.results_text.insert(tk.END, line + "\n", 'error')
            else:
                self.results_text.insert(tk.END, line + "\n")
                
        # Add score guide
        self.results_text.insert(tk.END, "\n📘 Threat Score Guide:\n", 'header')
        self.results_text.insert(tk.END, "- 0–30   ✅ Safe\n", 'score_safe')
        self.results_text.insert(tk.END, "- 31–60  ⚠️ Caution\n", 'score_caution')
        self.results_text.insert(tk.END, "- 61–80  ❗ Suspicious\n", 'score_suspicious')
        self.results_text.insert(tk.END, "- 81–100 🚨 Dangerous\n", 'score_danger')
        
        self.results_text.insert(tk.END, "\n")
        self.results_text.see(tk.END)
        self.results_text.config(state='disabled')
        
    def open_url(self, event):
        """Open URL in default browser when clicked"""
        widget = event.widget
        index = widget.index(f"@{event.x},{event.y}")
        line_start = index.split(".")[0] + ".0"
        line_end = index.split(".")[0] + ".end"
        line = widget.get(line_start, line_end)
        
        # Extract URL from the line
        url_match = re.search(r"(https?://\S+)", line)
        if url_match:
            url = url_match.group(0)
            webbrowser.open_new_tab(url)

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingToolApp(root)
    root.mainloop()
