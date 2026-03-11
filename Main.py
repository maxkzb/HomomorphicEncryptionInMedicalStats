import pandas as pd
import numpy as np
import tenseal as ts
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

#functionalities
#1) performing secure statistical operations using he (for patients count, average age, disease count, and prevalence)
#2) patient can view his results
#3) doctor can view his patients results + stats
#4) work only on encrypted data and allow the doctor to write new patients or
# change existing patients data and save it already encrypted !
# , but then generating of the key would be problematic because it should be done only once and then reuse it?
# maybe just save the key somewhere but then is it really safe?


context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[60, 40, 40, 60]
)
context.generate_galois_keys()
context.global_scale = 2 ** 40


class SecureMedicalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Privacy-Preserving Medical System")
        self.root.geometry("1150x750")

        # Load Dataset
        self.FILENAME = "heart_disease_uci.csv"
        try:
            self.df = pd.read_csv(self.FILENAME, na_values=['?'])
            self.df['age'] = pd.to_numeric(self.df['age'], errors='coerce').fillna(self.df['age'].median())
            self.df['num'] = pd.to_numeric(self.df['num'], errors='coerce').fillna(0)
            self.df['trestbps'] = pd.to_numeric(self.df['trestbps'], errors='coerce').fillna("N/A")
            self.df['chol'] = pd.to_numeric(self.df['chol'], errors='coerce').fillna("N/A")
            self.clinics = ["All Clinics"] + sorted(self.df['dataset'].unique().tolist())
        except Exception as e:
            messagebox.showerror("Critical Error", f"Could not load {self.FILENAME}\n{e}")
            self.root.destroy()

        self.show_login_panel()

    def clear_screen(self):
        """Clears all widgets from the root window for fresh transitions."""
        for widget in self.root.winfo_children():
            widget.destroy()

    # --- SCREEN 1: LOGIN PANEL ---
    def show_login_panel(self):
        self.clear_screen()
        self.root.geometry("400x550")
        tk.Label(self.root, text="🛡️ Secure Portal", font=("Helvetica", 24, "bold")).pack(pady=40)

        p_frame = tk.LabelFrame(self.root, text="Patient Login", padx=20, pady=20)
        p_frame.pack(pady=10, fill="x", padx=40)

        tk.Label(p_frame, text="Enter Patient ID:").pack()
        self.patient_id_entry = tk.Entry(p_frame, justify='center', bg="white", fg="black", insertbackground="black",
                                         highlightthickness=1)
        self.patient_id_entry.pack(pady=5)
        self.patient_id_entry.insert(0, "1")

        tk.Button(p_frame, text="View My Results", command=self.login_as_patient, highlightbackground="#d1d1d1").pack(
            fill="x", pady=10)

        tk.Label(self.root, text="— OR —", fg="gray").pack(pady=10)

        d_frame = tk.LabelFrame(self.root, text="Medical Staff", padx=20, pady=20)
        d_frame.pack(pady=10, fill="x", padx=40)
        tk.Button(d_frame, text="Login as Doctor", command=self.show_doctor_dashboard,
                  highlightbackground="#d1d1d1").pack(fill="x", pady=5)

    def login_as_patient(self):
        try:
            p_id = int(self.patient_id_entry.get())
            if p_id in self.df['id'].values:
                self.show_patient_results(p_id)
            else:
                messagebox.showerror("Error", "Patient ID not found.")
        except ValueError:
            messagebox.showerror("Error", "Please enter a numeric ID.")

    # --- SCREEN 2: PATIENT RESULTS ---
    def show_patient_results(self, p_id):
        self.clear_screen()
        self.root.geometry("500x550")
        row = self.df[self.df['id'] == p_id].iloc[0]

        tk.Label(self.root, text=f"Patient Record: #{p_id}", font=("Helvetica", 18, "bold")).pack(pady=20)

        details_frame = tk.Frame(self.root, relief="groove", borderwidth=2, padx=20, pady=20)
        details_frame.pack(pady=10, padx=30, fill="both")

        status = "Heart Disease Detected" if row['num'] > 0 else "Clear / Healthy"
        color = "#c0392b" if row['num'] > 0 else "#27ae60"

        fields = [("Age:", int(row['age'])), ("Sex:", row['sex']), ("Clinic:", row['dataset']),
                  ("BP:", f"{row['trestbps']} mmHg"), ("Cholesterol:", f"{row['chol']} mg/dL"), ("Status:", status)]

        for label, value in fields:
            f = tk.Frame(details_frame)
            f.pack(fill="x", pady=5)
            tk.Label(f, text=label, font=("Helvetica", 11, "bold")).pack(side="left")
            tk.Label(f, text=str(value), font=("Helvetica", 11), fg=color if "Status" in label else "black").pack(
                side="right")

        tk.Button(self.root, text="← Logout", command=self.show_login_panel).pack(pady=30)

    # --- SCREEN 3: DOCTOR DASHBOARD ---
    def show_doctor_dashboard(self):
        self.clear_screen()
        self.root.geometry("1150x750")

        header = tk.Frame(self.root, bg="#2c3e50")
        header.pack(fill="x")
        tk.Label(header, text="Doctor's Administrative Dashboard", fg="white", bg="#2c3e50",
                 font=("Helvetica", 16)).pack(pady=15)

        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # LEFT SIDE: Browser & Filters
        left_side = tk.Frame(main_frame)
        left_side.pack(side="left", fill="both", expand=True)

        filter_frame = tk.Frame(left_side)
        filter_frame.pack(fill="x", pady=5)

        # ID Search
        tk.Label(filter_frame, text="Search ID:").pack(side="left", padx=2)
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.update_treeview())
        tk.Entry(filter_frame, textvariable=self.search_var, bg="white", fg="black", width=10).pack(side="left", padx=5)

        # Clinic Filter
        tk.Label(filter_frame, text="Clinic:").pack(side="left", padx=2)
        self.clinic_filter = ttk.Combobox(filter_frame, values=self.clinics, state="readonly", width=12)
        self.clinic_filter.set("All Clinics")
        self.clinic_filter.bind("<<ComboboxSelected>>", lambda e: self.update_treeview())
        self.clinic_filter.pack(side="left", padx=5)

        # Diagnosis Filter
        tk.Label(filter_frame, text="Status:").pack(side="left", padx=2)
        self.diag_filter = ttk.Combobox(filter_frame, values=["All", "Healthy", "Disease"], state="readonly", width=10)
        self.diag_filter.set("All")
        self.diag_filter.bind("<<ComboboxSelected>>", lambda e: self.update_treeview())
        self.diag_filter.pack(side="left", padx=5)

        # Table
        list_frame = tk.LabelFrame(left_side, text="Patient Database", padx=5, pady=5)
        list_frame.pack(fill="both", expand=True)

        cols = ("ID", "Age", "Sex", "Clinic", "Diagnosis")
        self.tree = ttk.Treeview(list_frame, columns=cols, show='headings')
        for col in cols: self.tree.heading(col, text=col)
        self.tree.column("ID", width=60);
        self.tree.column("Age", width=60)

        tree_scb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=tree_scb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.on_doctor_select_patient)

        # RIGHT SIDE: Analysis
        right_side = tk.Frame(main_frame, width=380)
        right_side.pack(side="right", fill="both", expand=False, padx=10)
        right_side.pack_propagate(False)

        self.sel_frame = tk.LabelFrame(right_side, text="Selected Record Details", padx=10, pady=10)
        self.sel_frame.pack(fill="x", pady=5)
        self.sel_label = tk.Label(self.sel_frame, text="Select a patient\nfrom the database", justify="left",
                                  font=("Courier", 10))
        self.sel_label.pack()

        he_frame = tk.LabelFrame(right_side, text="Secure Population Analytics (HE)", padx=10, pady=10)
        he_frame.pack(fill="both", expand=True, pady=5)

        tk.Label(he_frame, text="🔐 Aggregating data across all clinics\nwhile remaining encrypted.",
                 font=("Helvetica", 9, "italic")).pack()

        self.btn_he = tk.Button(he_frame, text="Compute Global Stats", command=self.run_he_thread)
        self.btn_he.pack(fill="x", pady=10)

        self.pb = ttk.Progressbar(he_frame, mode="determinate")
        self.pb.pack(fill="x", pady=5)

        self.he_status = tk.Label(he_frame, text="Status: Ready", fg="gray")
        self.he_status.pack()

        self.he_results = tk.Label(he_frame, text="", font=("Courier", 10), justify="left", bg="#f4f4f4",
                                   relief="sunken", pady=10, wraplength=340)
        self.he_results.pack(fill="both", expand=True, pady=10)

        tk.Button(self.root, text="Logout", command=self.show_login_panel).pack(pady=10)
        self.update_treeview()

    def update_treeview(self):
        query = self.search_var.get().lower()
        filter_diag = self.diag_filter.get()
        filter_clinic = self.clinic_filter.get()

        self.tree.delete(*self.tree.get_children())

        for _, row in self.df.iterrows():
            diag_str = "Positive" if row['num'] > 0 else "Negative"

            # Application of Filters
            if query and query not in str(row['id']).lower(): continue
            if filter_diag == "Healthy" and row['num'] > 0: continue
            if filter_diag == "Disease" and row['num'] == 0: continue
            if filter_clinic != "All Clinics" and row['dataset'] != filter_clinic: continue

            self.tree.insert("", "end", values=(int(row['id']), int(row['age']), row['sex'], row['dataset'], diag_str))

    def on_doctor_select_patient(self, event):
        selected = self.tree.selection()
        if not selected: return
        p_id = self.tree.item(selected[0])['values'][0]
        row = self.df[self.df['id'] == p_id].iloc[0]
        diag = "POSITIVE (Heart Issues)" if row['num'] > 0 else "NEGATIVE (Clear)"

        info = (f"PATIENT ID: {p_id}\n"
                f"CLINIC:     {row['dataset']}\n"
                f"AGE/SEX:    {int(row['age'])} / {row['sex']}\n"
                f"BP:         {row['trestbps']}\n"
                f"CHOL:       {row['chol']}\n"
                f"DIAGNOSIS:  {diag}")
        self.sel_label.config(text=info, fg="#c0392b" if row['num'] > 0 else "#27ae60")

    def run_he_thread(self):
        self.btn_he.config(state="disabled")
        threading.Thread(target=self.perform_he, daemon=True).start()

    def perform_he(self):
        try:
            self.he_status.config(text="Status: 🔐 Encrypting records...", fg="#e67e22")
            self.pb['value'] = 25

            ages = self.df['age'].tolist()
            disease = (self.df['num'] > 0).astype(float).tolist()

            enc_ages = ts.ckks_vector(context, ages)
            enc_disease = ts.ckks_vector(context, disease)

            self.he_status.config(text="Status: ⚙️ Computing on Ciphertext...", fg="#e67e22")
            self.pb['value'] = 60
            time.sleep(1)

            enc_avg_age = enc_ages.sum() * (1 / len(ages))
            enc_total_dis = enc_disease.sum()

            self.he_status.config(text="Status: 🔓 Final Decryption...", fg="#e67e22")
            self.pb['value'] = 90

            res_age = enc_avg_age.decrypt()[0]
            res_dis = round(enc_total_dis.decrypt()[0])

            self.he_status.config(text="Status: ✅ Analysis Complete", fg="green")
            self.pb['value'] = 100

            stats = (f"TOTAL PATIENTS: {len(self.df)}\n"
                     f"AVERAGE AGE:    {res_age:.2f}\n"
                     f"DISEASE COUNT:  {res_dis}\n"
                     f"PREVALENCE:     {(res_dis / len(self.df)) * 100:.1f}%")
            self.he_results.config(text=stats)
        except Exception as e:
            messagebox.showerror("HE Error", str(e))
        finally:
            self.btn_he.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMedicalApp(root)
    root.mainloop()