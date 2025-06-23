import tkinter as tk
from tkinter import ttk
from gui.ca_tab import create_ca_tab
from gui.signed_cert_tab import create_signed_cert_tab

def main():
    root = tk.Tk()
    root.title("Certificate Generator")
    root.geometry("800x600")
    root.resizable(True, True)

    notebook = ttk.Notebook(root)

    ca_frame = ttk.Frame(notebook)
    signed_frame = ttk.Frame(notebook)

    create_ca_tab(ca_frame)
    create_signed_cert_tab(signed_frame)

    notebook.add(ca_frame, text="Create CA Certificate")
    notebook.add(signed_frame, text="Create Signed Certificate")

    notebook.pack(expand=1, fill='both')

    root.mainloop()

if __name__ == "__main__":
    main()
