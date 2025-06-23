# SSL-Certificate-Generator
Self-signed SSL Certificate Generator with GUI
# 🔐 Certificate Generator – Python GUI for SSL & CA Certificates

**Certificate Generator** is a cross-platform Python GUI tool that helps you create SSL/TLS certificates and certificate authorities (CAs) with ease. It supports exporting to common formats like `.crt`, `.cer`, `.der`, `.pfx`, and `.p7b`, making it ideal for sysadmins, developers, and IT professionals.

---

## ✅ Features

- Create a self-signed **Certificate Authority (CA)**
- Generate **SSL certificates** signed by your CA
- Export to multiple formats:
  - `.crt`, `.cer`, `.der`, `.pfx` (PKCS#12), `.p7b` (PKCS#7)
- Optional password-protection for `.pfx` files
- Scrollable GUI with tabs for CA and certificate generation
- Compatible with Windows and Linux
- Portable: No installation required

---

## ⚙️ Requirements

- **Python 3.8+**
- **OpenSSL** installed and available in system `PATH`  
  _Required for `.p7b` (PKCS#7) certificate generation._
