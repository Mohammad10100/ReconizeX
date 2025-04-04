# ReconizeX ⚔️ – Unveiling Hidden Vulnerabilities in Android Apps
### For Static Analysis 🎯

Template Based Static Analysis of Android Applications 

A powerful tool for statically analyzing Android applications and detecting sensitive information, insecure coding patterns, and misconfigurations using Nuclei templates.

Find secrets, keys, weak coding practices & many more. Check [Features](https://github.com/utkarsh24122/apknuke#features-) & [Screenshots](https://github.com/mohammad10100/ReconizeX#-screenshots)

These templates are derived from open-source mobile-nuclei-templates by Optiv Security and [@0xgaurang](https://twitter.com/0xgaurang)
This App is inspired from [apknuke](https://github.com/utkarsh24122/apknuke)


# ⚙ Setup

1. Clone the repository and navigate into the directory:
```
$ git clone https://github.com/Mohammad10100/ReconizeX.git
$ cd ReconizeX
$ chmod +x reconizex.py
```
2. install dependencies:
install apktool ([Read How](https://ibotpeaches.github.io/Apktool/install/))
required: [python](https://www.python.org/downloads/)
required: [nuclei](https://github.com/projectdiscovery/nuclei)

3. Templates:
Use the included templates, your custom ones, or official ones from [optive](https://github.com/optiv/mobile-nuclei-templates). Update the template path in the script if needed:
Update the template path in the script if needed:
```
PATH_TO_NucleiTemplates="/[path]/mobile-nuclei-templates-i/"
```

# 💻 Usage 
## Intense Mode
```
python3 reconizex.py <target.apk>
# Example:
python3 reconizex.py app.apk
```

## Restricted Mode
```
python3 reconizex.py <target.apk> -r <your.package.name>
# Example:
python3 reconizex.py app.apk -r com.example.app
```

## Exporting a json file for API integration
```
python3 reconizex.py <target.apk> -o output.txt -je results.json
```

## 🛠️ Command Line Help
```
usage: reconizex.py [-h] [-r PACKAGE] [-o OUTPUT] [-je JSONEXPORT] apk

ReconizeX - Android APK Vulnerability Scanner

positional arguments:
  apk                   Path to target APK file

optional arguments:
  -h, --help            Show this help message and exit
  -r, --restrict        Package name for restricted scan mode
  -o, --output          Output file name for text report
  -je, --jsonexport     Export scan results in JSON format
  ```

You can combine `-o` and `-je` to get both text and JSON outputs.


# Features ✨

- Checks for :

 AWS Access Key ID 
 
 Twitter Secret 
 
 Mailchimp API Key 
 
 Square OAuth Secret 
 
 Dynatrace Token 
 
 Shopify Custom App Access Token 
 
 Cloudinary Basic Auth 
 
 Linkedin Client ID 
 
 S3 Bucket Detect 
 
 Slack API Key 
 
 Shopify Private App Access Token 
 
 Firebase Database Detect 
 
 Google API key 
 
 Square Accesss Token 
 
 Facebook Client ID 
 
 Basic Auth Credentials 
 
 Facebook Secret Key 
 
 Twilio API Key 
 
 Sendgrid API Key 
 
 Slack Webhook 
 
 Google Maps API keys
 
 Amazon MWS Auth Token 
 
 Shopify Shared Secret 
 
 Private Key Detect 
 
 Paypal Braintree Access Token 
 
 Shopify Access Token 
 
 Stripe API Key 
 
 Pictatic API Key 
 
 Mailgun API Key 
 
 AWS Cognito Pool ID 
 
 Biometric or Fingerprint detect 
 
 Webview JavaScript enabled 
 
 Webview loadUrl usage 
 
 ADB Backup Enabled 
 
 Webview addJavascript Interface Usage 
 
 File Scheme Enabled 
 
 Content Scheme Enabled 
 
 Webview Universal Access enabled 
 
 Improper Certificate Validation 
 
 Insecure Provider Path 
 
 Dynamic Registered Broadcast Receiver 
 
 Android Debug Enabled 
 
 Cleartext Storage
 
 Clipboard Data Leak
 
 Custom Permissions
 
 Hardcoded Crypto Keys
 
 Insecure Random
 
 Log Sensitive Data
 
 Path Traversal
 
 RSA Without OAEP
 
 Smali Broadcast Receiver
 
 Smali Command Execution
 
 Smali Log Injection
 
 Smali OS Command Injection
 
 Smali Unsafe Deserialization
 
 SQL Injection
 
 SSL Misconfiguration
 
 Tapjacking  


# 📈 HTML Reporting (New!)

A fully styled, interactive HTML report (report.html) is auto-generated when used with JSON export.
Features:

    Sort by severity, template ID, or URL

    Hacker-style themed UI with green flicker animation

    No external dependencies — 100% client-side
 

# 📷 Screenshots
![screenshot](https://github.com/user-attachments/assets/ec89f00c-4e8e-46b2-a101-7e3b3ebad069)
![screenshotui](https://github.com/user-attachments/assets/d8f666b8-1808-4487-b4e0-0132f1611bfd)
