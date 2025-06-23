import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
import os
import subprocess
import tempfile
import ssl

def create_signed_cert_tab(parent):
    canvas = tk.Canvas(parent)
    scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)

    scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    fields = {}
    labels = [
        "Country", "State", "Locality", "Organization",
        "Department", "Common Name", "Email", "Validity Days", "SAN (comma-separated)"
    ]

    for i, label in enumerate(labels):
        ttk.Label(scrollable_frame, text=label).grid(row=i, column=0, sticky="e", padx=5, pady=3)
        entry = ttk.Entry(scrollable_frame, width=50)
        entry.grid(row=i, column=1, padx=5, pady=3)
        fields[label] = entry

    row = len(labels)

    # Certificate Purposes
    ttk.Label(scrollable_frame, text="Certificate Purposes (EKU):").grid(row=row, column=0, sticky="nw", padx=5)
    eku_opts = {
        "Server Authentication": ExtendedKeyUsageOID.SERVER_AUTH,
        "Client Authentication": ExtendedKeyUsageOID.CLIENT_AUTH,
        "Code Signing": ExtendedKeyUsageOID.CODE_SIGNING,
        "Email Protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    }
    eku_vars = {}
    eku_frame = ttk.Frame(scrollable_frame)
    eku_frame.grid(row=row, column=1, sticky="w", padx=5)
    for i, (name, oid) in enumerate(eku_opts.items()):
        var = tk.BooleanVar()
        ttk.Checkbutton(eku_frame, text=name, variable=var).grid(row=i, column=0, sticky="w")
        eku_vars[oid] = var
    row += 1

    # CA Certificate
    ttk.Label(scrollable_frame, text="CA Certificate (PEM or CRT):").grid(row=row, column=0, sticky="e")
    ca_cert_path = tk.StringVar()
    ttk.Entry(scrollable_frame, textvariable=ca_cert_path, width=50).grid(row=row, column=1, padx=5)
    ttk.Button(
        scrollable_frame,
        text="Browse",
        command=lambda: ca_cert_path.set(
            filedialog.askopenfilename(
                title="Select CA Certificate",
                filetypes=[("Certificate Files", "*.pem *.crt"), ("All files", "*.*")]
            )
        )
    ).grid(row=row, column=2)
    row += 1

    # CA Private Key
    ttk.Label(scrollable_frame, text="CA Private Key (PEM):").grid(row=row, column=0, sticky="e")
    ca_key_path = tk.StringVar()
    ttk.Entry(scrollable_frame, textvariable=ca_key_path, width=50).grid(row=row, column=1, padx=5)
    ttk.Button(scrollable_frame, text="Browse", command=lambda: ca_key_path.set(filedialog.askopenfilename())).grid(row=row, column=2)
    row += 1

    # Output File
    ttk.Label(scrollable_frame, text="Output File:").grid(row=row, column=0, sticky="e")
    output_path = tk.StringVar()
    ttk.Entry(scrollable_frame, textvariable=output_path, width=50).grid(row=row, column=1, padx=5)

    def browse_output_file():
        filetypes = [
            ("All Cert Formats", "*.crt *.cer *.pem *.pfx *.p7b *.der"),
            ("PEM", "*.pem"), ("CRT", "*.crt"), ("CER", "*.cer"),
            ("PFX", "*.pfx"), ("P7B", "*.p7b"), ("DER", "*.der")
        ]
        filename = filedialog.asksaveasfilename(
            title="Save Certificate As",
            filetypes=filetypes,
            defaultextension=".pem"
        )
        if filename:
            ext = os.path.splitext(filename)[1]
            if not ext:
                # Fall back to default extension (defaultextension handles most cases)
                filename += ".pem"
            output_path.set(filename)

    ttk.Button(scrollable_frame, text="Browse", command=browse_output_file).grid(row=row, column=2)
    row += 1

    # PFX Password
    ttk.Label(scrollable_frame, text="PFX Password:").grid(row=row, column=0, sticky="e")
    pfx_password = ttk.Entry(scrollable_frame, show="*")
    pfx_password.grid(row=row, column=1, padx=5, sticky="w")
    row += 1

    # Legacy SHA1
    legacy_var = tk.BooleanVar()
    legacy_checkbox = ttk.Checkbutton(scrollable_frame, text="Legacy Mode (SHA1 Signature)", variable=legacy_var)
    legacy_checkbox.grid(row=row, column=0, columnspan=2, sticky="w", padx=5)

    # Disable legacy if SHA1 is not supported
    if ssl.OPENSSL_VERSION_INFO >= (3, 0):
        legacy_checkbox.configure(state="disabled")
        ttk.Label(
            scrollable_frame,
            text="⚠ SHA1 signing disabled in OpenSSL 3.0+",
            foreground="orange"
        ).grid(row=row + 1, column=0, columnspan=2, sticky="w", padx=25)
        row += 1
    row += 1

    # PKCS12 chain
    include_chain = tk.BooleanVar()
    ttk.Checkbutton(scrollable_frame, text="Include CA chain in PFX (PKCS#12)", variable=include_chain).grid(
        row=row, column=0, columnspan=2, sticky="w", padx=5)
    row += 1

    # Generate
    def generate():
        try:
            with open(ca_cert_path.get(), "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            with open(ca_key_path.get(), "rb") as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)

            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, fields["Country"].get()),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, fields["State"].get()),
                x509.NameAttribute(NameOID.LOCALITY_NAME, fields["Locality"].get()),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, fields["Organization"].get()),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, fields["Department"].get()),
                x509.NameAttribute(NameOID.COMMON_NAME, fields["Common Name"].get()),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, fields["Email"].get()),
            ])

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            now = datetime.utcnow()
            cert_builder = x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject)\
                .public_key(key.public_key()).serial_number(x509.random_serial_number())\
                .not_valid_before(now).not_valid_after(now + timedelta(days=int(fields["Validity Days"].get())))

            sans = [x509.DNSName(s.strip()) for s in fields["SAN (comma-separated)"].get().split(",") if s.strip()]
            if sans:
                cert_builder = cert_builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)

            eku_oids = [oid for oid, var in eku_vars.items() if var.get()]
            if eku_oids:
                cert_builder = cert_builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=False)

            algo = hashes.SHA1() if legacy_var.get() else hashes.SHA256()
            cert = cert_builder.sign(private_key=ca_key, algorithm=algo)

            out = output_path.get().strip()
            if not out:
                messagebox.showerror("Error", "No output file selected.")
                return

            ext = os.path.splitext(out)[1].lower()

            if ext in [".pem", ".crt"]:
                with open(out, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                with open(out.replace(ext, "_key.pem"), "wb") as f:
                    f.write(key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ))

            elif ext in [".cer", ".der"]:
                with open(out, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.DER))
                with open(out.replace(ext, "_key.pem"), "wb") as f:
                    f.write(key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ))

            elif ext == ".pfx":
                pwd = pfx_password.get().encode() if pfx_password.get() else None
                pfx = pkcs12.serialize_key_and_certificates(
                    name=b"cert",
                    key=key,
                    cert=cert,
                    cas=[ca_cert] if include_chain.get() else None,
                    encryption_algorithm=serialization.BestAvailableEncryption(pwd) if pwd else serialization.NoEncryption()
                )
                with open(out, "wb") as f:
                    f.write(pfx)

            elif ext == ".p7b":
                cert_temp = tempfile.NamedTemporaryFile("wb", delete=False, suffix=".pem")
                ca_temp = tempfile.NamedTemporaryFile("wb", delete=False, suffix=".pem")
                try:
                    cert_temp.write(cert.public_bytes(serialization.Encoding.PEM))
                    ca_temp.write(ca_cert.public_bytes(serialization.Encoding.PEM))
                    cert_temp.close()
                    ca_temp.close()

                    cmd = [
                        "openssl", "crl2pkcs7", "-nocrl",
                        "-certfile", cert_temp.name,
                        "-certfile", ca_temp.name if include_chain.get() else cert_temp.name,
                        "-outform", "DER", "-out", out
                    ]
                    result = subprocess.run(cmd, capture_output=True)
                    if result.returncode != 0:
                        raise RuntimeError(result.stderr.decode())
                finally:
                    os.unlink(cert_temp.name)
                    os.unlink(ca_temp.name)

                    if result.returncode != 0:
                        raise RuntimeError(result.stderr.decode())

            else:
                messagebox.showerror("Error", f"Unsupported format: {ext}")
                return

            messagebox.showinfo("Success", f"Certificate saved to:\n{out}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    ttk.Button(scrollable_frame, text="Generate Signed Certificate", command=generate)\
        .grid(row=row, column=0, columnspan=3, pady=15)
