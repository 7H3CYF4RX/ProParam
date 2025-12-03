# ProParam 🚀

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Author](https://img.shields.io/badge/author-7H3CYF4RX-red.svg)

**Author:** Muhammed Farhan (7H3CYF4RX)

**ProParam** is a powerful, professional Burp Suite extension for advanced parameter discovery and cache poisoning detection. It goes beyond traditional parameter miners with intelligent detection, comprehensive cache analysis, and automatic proof-of-concept generation.

---

## 🎯 What is ProParam?

**ProParam** (Professional Parameter Miner) is your go-to tool for:
- 🔍 **Smart Parameter Discovery** - Query, POST, JSON, headers, cookies
- ⚡ **Cache Poisoning Detection** - 4 vulnerability types with auto-verification
- 🎨 **Modern UI** - Beautiful 5-panel interface
- 🤖 **Intelligent Analysis** - False-positive reduction with multi-layer validation
- 📊 **Professional Reports** - Auto-generated PoCs and Burp issue creation

---

## ✨ Key Features

### Parameter Discovery Engine
✅ **Query Parameters** - Intelligent brute-forcing with context-aware wordlists  
✅ **POST Body Parameters** - Form-encoded, JSON, and XML parameter discovery  
✅ **HTTP Headers** - Comprehensive header testing (80+ headers)  
✅ **Cookie Parameters** - Cookie manipulation and discovery  
✅ **4-Tier Wordlist System** - Fast (100) → Normal (500) → Deep (2000) → Exhaustive (5000+)  

### Cache Poisoning Detection  
✅ **Unkeyed Header Detection** - Tests 15+ critical headers  
✅ **Parameter Cloaking** - Detects when parameter names matter but values don't  
✅ **Fat GET Detection** - Identifies GET requests with bodies that are cached  
✅ **Cache Deception** - Tests for web cache deception vulnerabilities  

### Multi-Vendor Cache Fingerprinting
✅ Cloudflare • Akamai • Fastly • Varnish • Nginx • CloudFront • Apache Traffic Server • Custom

### Smart Analysis
✅ **Response Normalization** - Automatically removes dynamic content (timestamps, UUIDs, CSRF tokens)  
✅ **Differential Analysis** - Smart comparison using Levenshtein distance  
✅ **Cache TTL Extraction** - Identifies cache duration  
✅ **Automatic PoC Generation** - Ready-to-use exploitation guides  

---

## 📦 Installation

### Option 1: BApp Store (Coming Soon)
1. Open Burp Suite
2. Go to **Extender** → **BApp Store**
3. Search for "ProParam"
4. Click **Install**

### Option 2: Manual Installation
1. Download `proparam-1.0.0.jar` from [Releases](#)
2. Open Burp Suite
3. Go to **Extender** → **Extensions**
4. Click **Add**
5. Select the downloaded JAR file
6. Click **Next**

### Option 3: Build from Source
```bash
git clone https://github.com/7H3CYF4RX//ProParam.git
cd proparam
gradle jar
# Output: build/libs/proparam-1.0.0.jar
```

---

## 🚀 Quick Start

### Basic Scan
1. Navigate to any HTTP request in Burp (Proxy, Target, etc.)
2. Right-click the request
3. Select **Scan with ProParam**
4. View results in the **ProParam** tab

### Quick Scan (Faster)
- Right-click → **Quick Scan (Fast mode)**
- Uses smaller wordlist for rapid testing

### Cache Analysis
- Right-click → **Analyze Cache Behavior**
- Provides detailed cache system fingerprinting and vulnerability detection

---

## 🎨 User Interface

ProParam features a modern, tabbed interface:

### 📊 **Dashboard**
- Real-time statistics
- Active scans overview
- Quick actions panel

### 📋 **Scan Results**
- Sortable/filterable table
- Color-coded severity
- Context menu (View Details, Generate PoC, Send to Repeater)

### 🔍 **Cache Analysis**
- Visual cache system detection
- TTL display
- Keyed vs Unkeyed components
- Security warnings

### ⚙️ **Configuration**
- Scan settings (threads, delays)
- Discovery options (wordlist tiers)
- Cache detection toggles
- Reporting preferences

### 📝 **Logs**
- Real-time scan feedback
- Error tracking

---

## ⚙️ Configuration

Access configuration via the **Configuration** tab:

### Scan Settings
- **Thread Count** (1-50): Number of concurrent requests
- **Request Delay** (0-5000ms): Delay between requests
- **Follow Redirects**: Whether to follow HTTP redirects
- **In-Scope Only**: Limit scanning to Burp's defined scope

### Discovery Settings
- **Wordlist Tier**: Choose scan depth
  - `Fast` (100 params): Quick scan
  - `Normal` (500 params): Balanced approach
  - `Deep` (2000 params): Thorough testing
  - `Exhaustive` (5000+ params): Complete coverage
- **Include Headers**: Test HTTP headers
- **Include Cookies**: Test cookie parameters
- **Include JSON Parameters**: Test JSON body params

### Cache Poisoning Settings
- **Enable Cache Analysis**: Perform cache detection
- **Auto-Verify Findings**: Validate discoveries automatically
- **Cache Stability Tests** (1-10): Number of verification attempts
- **Detection Modules**:
  - Unkeyed Headers ✓
  - Parameter Cloaking ✓
  - Fat GET ✓
  - Cache Deception ✓

### Reporting
- **Auto-Generate PoCs**: Create exploitation guides
- **Create Burp Issues**: Add findings to Burp's issue tracker
- **Min Severity to Report**: Filter by severity level

---

## 📖 Examples

### Example 1: Finding Hidden API Parameters
```
Target: https://api.example.com/users
Mode: Normal scan
Result: Found "debug" parameter
Evidence: Response includes debug information (+1,200 bytes)
Impact: Information disclosure
```

### Example 2: Unkeyed Header Cache Poisoning
```
Target: https://www.example.com/
Cache System: Cloudflare
Finding: X-Forwarded-Host is unkeyed
PoC: 
  1. Send: X-Forwarded-Host: evil.com
  2. Response reflects evil.com
  3. Response is cached
Impact: XSS/Phishing via cache poisoning
```

### Example 3: Parameter Cloaking
```
Target: https://example.com/search
Finding: utm_content exhibits cloaking
Evidence:
  - ?utm_content=value1 → Response cached
  - ?utm_content=value2 → Same cached response served
Impact: Cache poisoning through parameter manipulation
```

---

## 🔧 Troubleshooting

### Extension Not Loading
- Check **Extender** → **Extensions** → **Errors** tab
- Ensure Java 11+ is installed
- Verify JAR file integrity

### No Results Found
- Increase wordlist tier to "Deep" or "Exhaustive"
- Add request delay if being rate-limited
- Verify target responds differently to parameters
- Check Burp scope settings

### False Positives
- Enable "Auto-Verify Findings" in configuration
- Increase stability test count
- Review baseline response for dynamic content

### Performance Issues
- Reduce thread count
- Use "Quick Scan" mode
- Increase request delay
- Select appropriate wordlist tier

---

## 🤝 Contributing

Contributions  are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- James Kettle (@albinowax) for pioneering research on web cache poisoning
- PortSwigger for the Burp Extender API
- The infosec community for continuous research and feedback

---

## 📧 Contact & Support

- **Author**: Muhammed Farhan (7H3CYF4RX)
- **Issues**: [GitHub Issues](#)
- **Documentation**: Full guide in this README

---

## 🔗 Resources

- [Web Cache Poisoning Research](https://portswigger.net/research/practical-web-cache-poisoning)
- [Burp Extender API](https://portswigger.net/burp/extender/api/)
- [Parameter Mining Techniques](https://portswigger.net/research/param-miner)

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Always obtain proper authorization before testing systems you don't own.

---

**Made with ❤️ by Muhammed Farhan (7H3CYF4RX)**

**ProParam** - Professional Parameter Mining & Cache Poisoning Detection 🚀

