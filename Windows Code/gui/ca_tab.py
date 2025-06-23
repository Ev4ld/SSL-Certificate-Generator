import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os


def create_ca_tab(frame):
    # Define fields for CA certificate creation
    fields = ["Country", "State", "Locality", "Organization", "Department", "Common Name", "Email"]
    entries = {}

    # Create label and entry for each field
    for i, field in enumerate(fields):
        label = ttk.Label(frame, text=field)
        label.grid(row=i, column=0, padx=10, pady=5, sticky='e')

        entry = ttk.Entry(frame)
        entry.grid(row=i, column=1, padx=10, pady=5, sticky='w')
        entries[field] = entry

    # Validity date fields
    valid_from_label = ttk.Label(frame, text="Valid From (YYYY-MM-DD):")
    valid_from_entry = ttk.Entry(frame)
    valid_from_entry.insert(0, datetime.today().strftime("%Y-%m-%d"))

    valid_days_label = ttk.Label(frame, text="Valid For (Days):")
    valid_days_entry = ttk.Entry(frame)
    valid_days_entry.insert(0, "365")

    valid_from_label.grid(row=len(fields), column=0, padx=10, pady=5, sticky='e')
    valid_from_entry.grid(row=len(fields), column=1, padx=10, pady=5, sticky='w')
    valid_days_label.grid(row=len(fields)+1, column=0, padx=10, pady=5, sticky='e')
    valid_days_entry.grid(row=len(fields)+1, column=1, padx=10, pady=5, sticky='w')

    # Path to save certificate and key
    save_path = tk.StringVar()

    # Choose where to save files
  
    def choose_save_location():
        filetypes = [
            ("CRT Certificate", "*.crt"),
            ("PEM Certificate", "*.pem"),
            ("All Files", "*.*")
        ]
        filename = filedialog.asksaveasfilename(
            title="Save CA Certificate",
            filetypes=filetypes,
            defaultextension=".crt"
        )
        if filename:
            ext = os.path.splitext(filename)[1]
            if not ext:
                filename += ".crt"
            save_path.set(filename)

    choose_path_button = ttk.Button(frame, text="Choose Save Location", command=choose_save_location)
    choose_path_button.grid(row=len(fields)+2, column=0, columnspan=2, pady=5)

    # Logic to generate the CA certificate
    def generate_ca_cert():
        if not save_path.get():
            messagebox.showerror("Missing Path", "Please choose a save location.")
            return

        try:
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, entries["Country"].get()),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, entries["State"].get()),
                x509.NameAttribute(NameOID.LOCALITY_NAME, entries["Locality"].get()),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, entries["Organization"].get()),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, entries["Department"].get()),
                x509.NameAttribute(NameOID.COMMON_NAME, entries["Common Name"].get()),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, entries["Email"].get())
            ])

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            valid_from = datetime.strptime(valid_from_entry.get(), "%Y-%m-%d")
            valid_days = int(valid_days_entry.get())
            valid_to = valid_from + timedelta(days=valid_days)

            cert = x509.CertificateBuilder()\
                .subject_name(subject)\
                .issuer_name(subject)\
                .public_key(private_key.public_key())\
                .serial_number(x509.random_serial_number())\
                .not_valid_before(valid_from)\
                .not_valid_after(valid_to)\
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
                .sign(private_key, hashes.SHA256())

            # Save the certificate
            with open(save_path.get(), "wb") as cert_file:
                cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

            # Save the private key
            key_path = os.path.splitext(save_path.get())[0] + ".key"
            with open(key_path, "wb") as key_file:
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            messagebox.showinfo("Success", f"CA Certificate saved to:\n{save_path.get()}\nPrivate Key: {key_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate CA Certificate:\n{e}")

    # ✅ This button generates the certificate
    generate_button = ttk.Button(frame, text="Generate CA Certificate", command=generate_ca_cert)
    generate_button.grid(row=len(fields)+3, column=0, columnspan=2, pady=10)
