# SSL-Certificate-Generator
Self-signed SSL Certificate Generator with GUI
# 🔐 Certificate Generator – Python GUI for SSL & CA Certificates

**Certificate Generator** is a cross-platform Python GUI tool that helps you create SSL/TLS certificates and certificate authorities (CAs) with ease. It supports exporting to common formats like `.crt`, `.cer`, `.der`, `.pfx`, and `.p7b`, making it ideal for sysadmins, developers, and IT professionals.

-![CA_tab](https://github.com/user-attachments/assets/5f13ddd3-98b3-45af-a078-1405bd39f2d5)
![signed_tab](https://github.com/user-attachments/assets/c7fbc020-078b-4335-a9ae-49ea8d90882c)

--

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

- **OpenSSL** installed and available in system `PATH`  
  _Required for `.p7b` (PKCS#7) certificate generation._

  ## 🚀 How to Use

### Run the Pre-built Executable (Recommended)

No Python or dependencies required.

- **Windows**: Download 'Certificate_Generator_ForWindows.exe'
- **Linux**: Download the Linux binary from releases

> Just make the file executable on Linux:
```bash
chmod +x Certificate_Generator_ForLinux
./Certificate_Generator_ForLinux
