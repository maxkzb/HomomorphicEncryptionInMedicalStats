import pandas as pd
import tenseal as ts
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import os
import pickle
import base64
import hashlib
import time
from datetime import datetime
from simple_keystore import SimpleKeyStore


class PureHEMedicalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Pure HE Vault - Thesis Final Edition")
        self.center_window(1300, 850)

        self.DB_FILE = "he_longitudinal_vault.pkl"
        self.RAW_FILE = "heart_disease_longitudinal.csv"
        self.KEYSTORE_FILE = "he_vault.db"

        self.he_context_ckks = None
        self.he_context_bfv = None
        self.enc_columns_ckks = {}
        self.enc_columns_bfv = {}
        self.plain_columns = {}

        self.apply_global_styles()
        self.init_security_and_data()

    def apply_global_styles(self):
        style = ttk.Style()
        # Ensure Treeview rows are nicely spaced
        style.configure("Treeview", rowheight=25, font=('Arial', 10))
        style.configure("Treeview.Heading", font=('Arial', 10, 'bold'))
        style.configure("TLabelframe.Label", font=('Arial', 11, 'bold'), foreground="#2c3e50")

    def center_window(self, width, height):
        # Get the screen width and height
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Calculate the starting X and Y coordinates for the center
        x = int((screen_width / 2) - (width / 2))
        y = int((screen_height / 2) - (height / 2)) - 40  # -40 pushes it slightly up so the taskbar doesn't block it

        # Set the dimensions and placement
        self.root.geometry(f'{width}x{height}+{x}+{y}')

    def get_keystore_token(self, password):
        digest = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8')

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def init_security_and_data(self):
        self.root.withdraw()

        if not os.path.exists(self.KEYSTORE_FILE) or not os.path.exists(self.DB_FILE):
            pwd = simpledialog.askstring("New Keystore", "Create Master Password to generate Dual-HE Vault:", show='*')
            if not pwd: self.root.destroy(); return

            os.environ['SIMPLE_KEYSTORE_KEY'] = self.get_keystore_token(pwd)

            # CKKS Context
            ctx_ckks = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
            ctx_ckks.generate_galois_keys()
            ctx_ckks.global_scale = 2 ** 40
            self.he_context_ckks = ctx_ckks

            # BFV Context
            ctx_bfv = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=8192, plain_modulus=1032193)
            ctx_bfv.generate_galois_keys()
            self.he_context_bfv = ctx_bfv

            ks = SimpleKeyStore(self.KEYSTORE_FILE)
            ks.add_key(name="sk_ckks", unencrypted_key=ctx_ckks.serialize(save_secret_key=True).hex())
            ks.add_key(name="sk_bfv", unencrypted_key=ctx_bfv.serialize(save_secret_key=True).hex())

            self.encrypt_raw_to_disk()
            messagebox.showinfo("Setup Complete", "Dual-Algorithm Vault generated successfully.")
        else:
            pwd = simpledialog.askstring("Unlock Keystore", "Enter Master Vault Password:", show='*')
            if not pwd: self.root.destroy(); return

            try:
                os.environ['SIMPLE_KEYSTORE_KEY'] = self.get_keystore_token(pwd)
                ks = SimpleKeyStore(self.KEYSTORE_FILE)
                self.he_context_ckks = ts.context_from(bytes.fromhex(ks.get_key_by_name("sk_ckks")))
                self.he_context_bfv = ts.context_from(bytes.fromhex(ks.get_key_by_name("sk_bfv")))
                self.load_he_vectors()
            except Exception as e:
                messagebox.showerror("Auth Failed", f"Incorrect Password or Keystore error.\n{e}")
                self.root.destroy();
                return

        self.root.deiconify()
        self.show_login_panel()

    def encrypt_raw_to_disk(self):
        try:
            df = pd.read_csv(self.RAW_FILE, na_values=['?'])
        except FileNotFoundError:
            messagebox.showerror("Error", f"Could not find {self.RAW_FILE}.")
            self.root.destroy();
            return

        df = df.sort_values(by=['id', 'date'])
        for col in ['age', 'trestbps', 'chol', 'num']:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

        bytes_ckks, bytes_bfv = {}, {}
        for col in ['age', 'trestbps', 'chol', 'num']:
            data_list = df[col].tolist()
            bytes_ckks[col] = ts.ckks_vector(self.he_context_ckks, data_list).serialize()
            bytes_bfv[col] = ts.bfv_vector(self.he_context_bfv, [int(x) for x in data_list]).serialize()

        auth_dict = {"admin": self.hash_password("doctor123")}
        history_dict = {}
        for p_id in df['id'].unique():
            auth_dict[int(p_id)] = self.hash_password("patient123")
            history_dict[int(p_id)] = [f"[{datetime.now().strftime('%Y-%m-%d')}] Record initialized."]

        plain_dict = {
            'id': df['id'].tolist(), 'date': df['date'].tolist(),
            'sex': df['sex'].tolist(), 'dataset': df['dataset'].tolist(),
            'auth': auth_dict, 'history': history_dict
        }

        with open(self.DB_FILE, "wb") as f:
            pickle.dump({"enc_ckks": bytes_ckks, "enc_bfv": bytes_bfv, "plain": plain_dict}, f)
        self.load_he_vectors()

    def save_vault(self):
        bytes_ckks = {k: v.serialize() for k, v in self.enc_columns_ckks.items()}
        bytes_bfv = {k: v.serialize() for k, v in self.enc_columns_bfv.items()}
        with open(self.DB_FILE, "wb") as f:
            pickle.dump({"enc_ckks": bytes_ckks, "enc_bfv": bytes_bfv, "plain": self.plain_columns}, f)

    def load_he_vectors(self):
        with open(self.DB_FILE, "rb") as f:
            data = pickle.load(f)
            self.plain_columns = data["plain"]
            self.enc_columns_ckks = {col: ts.ckks_vector_from(self.he_context_ckks, b) for col, b in
                                     data["enc_ckks"].items()}
            self.enc_columns_bfv = {col: ts.bfv_vector_from(self.he_context_bfv, b) for col, b in
                                    data["enc_bfv"].items()}

    def clear_screen(self):
        for widget in self.root.winfo_children(): widget.destroy()

    def wipe_vault_and_restart(self):
        if messagebox.askyesno("Warning", "Delete vault and keystore to start fresh?"):
            if os.path.exists(self.DB_FILE): os.remove(self.DB_FILE)
            if os.path.exists(self.KEYSTORE_FILE): os.remove(self.KEYSTORE_FILE)
            self.root.destroy()

    # --- LOGIN & PATIENT VIEWS ---
    def show_login_panel(self):
        self.clear_screen()
        self.center_window(600, 650)
        tk.Label(self.root, text="🛡️ Secure HE Vault Portal", font=("Arial", 24, "bold"), fg="#2c3e50").pack(pady=30)

        p_frame = ttk.LabelFrame(self.root, text="Patient Access", padding=20)
        p_frame.pack(pady=10, fill="x", padx=60)
        tk.Label(p_frame, text="Patient ID:").grid(row=0, column=0, pady=5, sticky="e")
        self.p_login_id = ttk.Entry(p_frame, width=20);
        self.p_login_id.grid(row=0, column=1, pady=5)
        tk.Label(p_frame, text="Password:").grid(row=1, column=0, pady=5, sticky="e")
        self.p_login_pwd = ttk.Entry(p_frame, width=20, show="*");
        self.p_login_pwd.grid(row=1, column=1, pady=5)
        tk.Button(p_frame, text="Login as Patient", command=self.auth_patient, bg="#3498db", fg="black").grid(row=2,
                                                                                                              column=0,
                                                                                                              columnspan=2,
                                                                                                              pady=10)

        d_frame = ttk.LabelFrame(self.root, text="Medical Staff", padding=20)
        d_frame.pack(pady=20, fill="x", padx=60)
        tk.Label(d_frame, text="Username:").grid(row=0, column=0, pady=5, sticky="e")
        self.d_login_usr = ttk.Entry(d_frame, width=20);
        self.d_login_usr.grid(row=0, column=1, pady=5)
        tk.Label(d_frame, text="Password:").grid(row=1, column=0, pady=5, sticky="e")
        self.d_login_pwd = ttk.Entry(d_frame, width=20, show="*");
        self.d_login_pwd.grid(row=1, column=1, pady=5)
        tk.Button(d_frame, text="Login as Doctor", command=self.auth_doctor, bg="#2ecc71", fg="black").grid(row=2,
                                                                                                            column=0,
                                                                                                            columnspan=2,
                                                                                                            pady=10)

        tk.Button(self.root, text="⚠️ Factory Reset Vault (Dev Tool)", command=self.wipe_vault_and_restart,
                  fg="red").pack(side="bottom", pady=20)

    def auth_patient(self):
        try:
            p_id = int(self.p_login_id.get())
            pwd = self.p_login_pwd.get()
            if p_id in self.plain_columns['auth'] and self.plain_columns['auth'][p_id] == self.hash_password(pwd):
                self.show_patient_view(p_id)
            else:
                messagebox.showerror("Denied", "Incorrect Credentials.")
        except ValueError:
            messagebox.showerror("Error", "Enter numeric ID.")

    def auth_doctor(self):
        usr = self.d_login_usr.get()
        pwd = self.d_login_pwd.get()
        if usr in self.plain_columns['auth'] and self.plain_columns['auth'][usr] == self.hash_password(pwd):
            self.show_doctor_dashboard()
        else:
            messagebox.showerror("Denied", "Invalid Credentials.")

    def show_patient_view(self, p_id):
        self.clear_screen()
        patient_indices = [i for i, x in enumerate(self.plain_columns['id']) if x == p_id]
        tk.Label(self.root, text=f"Historical Record: Patient #{p_id}", font=("Helvetica", 18, "bold")).pack(pady=10)

        cols = ("Date", "Age", "Clinic", "BP", "Chol", "Diagnosis")
        tree = ttk.Treeview(self.root, columns=cols, show='headings', height=6)
        for col in cols: tree.heading(col, text=col); tree.column(col, width=100, anchor="center")
        tree.pack(pady=10, padx=40, fill="x")

        ages = self.enc_columns_ckks['age'].decrypt()
        bps = self.enc_columns_ckks['trestbps'].decrypt()
        chols = self.enc_columns_ckks['chol'].decrypt()
        nums = self.enc_columns_ckks['num'].decrypt()

        patient_records = []
        for idx in patient_indices:
            sick = "DISEASE" if nums[idx] > 0.5 else "HEALTHY"
            patient_records.append((self.plain_columns['date'][idx], round(ages[idx]),
                                    self.plain_columns['dataset'][idx], round(bps[idx]), round(chols[idx]), sick))

        patient_records.sort(key=lambda x: x[0], reverse=True)
        for rec in patient_records: tree.insert("", "end", values=rec)

        tk.Label(self.root, text="Clinical History Notes:", font=("Helvetica", 12, "bold")).pack(pady=(10, 0))
        hist_box = tk.Text(self.root, height=8, width=70, bg="#f4f4f4", wrap=tk.WORD, font=("Arial", 10))
        hist_box.pack(pady=5)
        for note in self.plain_columns['history'][p_id]:
            hist_box.insert(tk.END, note + "\n\n")
        hist_box.config(state="disabled")

        tk.Button(self.root, text="Logout", command=self.show_login_panel, width=15).pack(pady=15)

    # --- DOCTOR DASHBOARD ---
    def show_doctor_dashboard(self):
        self.clear_screen()
        self.center_window(1300, 850)

        header = tk.Frame(self.root, bg="#2c3e50");
        header.pack(fill="x")
        tk.Label(header, text="Longitudinal EHR & HE Benchmarking", fg="white", bg="#2c3e50",
                 font=("Helvetica", 16)).pack(pady=10)

        main = tk.Frame(self.root);
        main.pack(fill="both", expand=True, padx=10, pady=5)

        # LEFT SIDE: Filtering & Data Table
        left = tk.Frame(main);
        left.pack(side="left", fill="both", expand=True)

        # --- NEW: FILTERING BAR ---
        filter_frame = tk.Frame(left)
        filter_frame.pack(fill="x", pady=5)

        tk.Label(filter_frame, text="🔍 ID:").pack(side="left")
        self.flt_id = ttk.Entry(filter_frame, width=8)
        self.flt_id.pack(side="left", padx=5)

        tk.Label(filter_frame, text="Sex:").pack(side="left")
        self.flt_sex = ttk.Combobox(filter_frame, values=["All", "Male", "Female"], state="readonly", width=8)
        self.flt_sex.set("All");
        self.flt_sex.pack(side="left", padx=5)

        tk.Label(filter_frame, text="Diagnosis:").pack(side="left")
        self.flt_diag = ttk.Combobox(filter_frame, values=["All", "Positive", "Negative"], state="readonly", width=10)
        self.flt_diag.set("All");
        self.flt_diag.pack(side="left", padx=5)

        tk.Button(filter_frame, text="Search", command=self.apply_filters, bg="#bdc3c7").pack(side="left", padx=5)
        tk.Button(filter_frame, text="Clear", command=self.clear_filters).pack(side="left")

        # Treeview UI
        cols = ("Date", "ID", "Sex", "Clinic", "BP", "Chol", "Diagnosis")
        self.tree = ttk.Treeview(left, columns=cols)
        self.tree.heading("#0", text="Visits");
        self.tree.column("#0", width=60, stretch=tk.NO, anchor="center")

        # POLISH: Centered columns
        for col in cols:
            self.tree.heading(col, text=col)
            # Make the ID and Date columns slightly wider, center everything else
            w = 90 if col in ["Date", "Clinic", "Diagnosis"] else 70
            self.tree.column(col, width=w, anchor="center")

        scb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scb.set);
        self.tree.pack(side="top", fill="both", expand=True, pady=5)
        scb.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self.on_doctor_select)

        # Initial Load of Table
        self.apply_filters()

        # RIGHT SIDE: History & Benchmarking
        right = tk.Frame(main, width=450);
        right.pack(side="right", fill="both", padx=10)
        right.pack_propagate(False)

        hist_frame = ttk.LabelFrame(right, text="Patient History & Notes", padding=10)
        hist_frame.pack(fill="x", pady=5)

        self.lbl_selected_id = tk.Label(hist_frame, text="Select a visit from the table to view.", fg="gray",
                                        font=("Arial", 10, "bold"))
        self.lbl_selected_id.pack(pady=2)

        self.txt_history = tk.Text(hist_frame, height=7, width=45, bg="#f4f4f4", font=("Arial", 9), wrap=tk.WORD)
        self.txt_history.pack(pady=5)
        self.txt_history.config(state="disabled")

        tk.Label(hist_frame, text="Append New Note:").pack(anchor="w")
        self.txt_new_note = tk.Text(hist_frame, height=3, width=45, wrap=tk.WORD)
        self.txt_new_note.pack(pady=2)

        tk.Button(hist_frame, text="Save Note to Vault", command=self.append_history).pack(pady=5)

        he_frame = ttk.LabelFrame(right, text="📊 Algorithm Benchmarking Suite", padding=15)
        he_frame.pack(fill="x", pady=10)

        tk.Label(he_frame, text="1. Select Metric:").grid(row=0, column=0, pady=5, sticky="e")
        self.metric_choice = ttk.Combobox(he_frame, values=["age", "trestbps", "chol", "num"], state="readonly",
                                          width=18)
        self.metric_choice.set("trestbps");
        self.metric_choice.grid(row=0, column=1, pady=5, padx=5)

        tk.Label(he_frame, text="2. Select Algorithm:").grid(row=1, column=0, pady=5, sticky="e")
        self.algo_choice = ttk.Combobox(he_frame, values=["CKKS (Approximate)", "BFV (Exact Integer)"],
                                        state="readonly", width=18)
        self.algo_choice.set("CKKS (Approximate)");
        self.algo_choice.grid(row=1, column=1, pady=5, padx=5)

        # POLISH: Clear old results when dropdowns change
        self.metric_choice.bind("<<ComboboxSelected>>", self.clear_bench_results)
        self.algo_choice.bind("<<ComboboxSelected>>", self.clear_bench_results)

        tk.Button(he_frame, text="▶ Run Benchmark", command=self.run_he_benchmark, bg="#e74c3c", fg="black").grid(row=2,
                                                                                                                  column=0,
                                                                                                                  columnspan=2,
                                                                                                                  pady=15)

        self.res_lab = tk.Label(he_frame, text="Result: --", font=("Arial", 12, "bold"), fg="#2980b9")
        self.res_lab.grid(row=3, column=0, columnspan=2, pady=5)

        self.time_lab = tk.Label(he_frame, text="Time: -- ms", font=("Courier", 10))
        self.time_lab.grid(row=4, column=0, columnspan=2, pady=5)

        tk.Button(self.root, text="Logout", command=self.show_login_panel, width=15).pack(pady=10)

    # --- FILTERING METHODS ---
    def clear_filters(self):
        self.flt_id.delete(0, tk.END)
        self.flt_sex.set("All")
        self.flt_diag.set("All")
        self.apply_filters()

    def apply_filters(self):
        f_id = self.flt_id.get().strip()
        f_sex = self.flt_sex.get()
        f_diag = self.flt_diag.get()
        # Run population in a background thread so UI doesn't freeze
        threading.Thread(target=self.populate_doctor_table, args=(f_id, f_sex, f_diag), daemon=True).start()

    def clear_bench_results(self, event):
        """Prevents displaying stale data when user changes the dropdown options."""
        self.res_lab.config(text="Result: --")
        self.time_lab.config(text="Time: -- ms")

    def on_doctor_select(self, event):
        sel = self.tree.selection()
        if not sel: return

        try:
            self.cur_selected_id = self.tree.item(sel[0])['values'][1]
            self.lbl_selected_id.config(text=f"Selected Patient: #{self.cur_selected_id}", fg="black")

            self.txt_history.config(state="normal")
            self.txt_history.delete("1.0", tk.END)
            if self.cur_selected_id in self.plain_columns['history']:
                for note in self.plain_columns['history'][self.cur_selected_id]:
                    self.txt_history.insert(tk.END, note + "\n\n")
            self.txt_history.config(state="disabled")
        except IndexError:
            pass  # Failsafe if they click an empty part of the tree

    def append_history(self):
        if not hasattr(self, 'cur_selected_id'):
            messagebox.showwarning("Warning", "Select a patient first.");
            return

        note = self.txt_new_note.get("1.0", tk.END).strip()
        if not note: return

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
        formatted_note = f"[{timestamp}] Staff Note:\n{note}"

        self.plain_columns['history'][self.cur_selected_id].append(formatted_note)
        self.save_vault()

        self.txt_new_note.delete("1.0", tk.END)
        self.txt_history.config(state="normal")
        self.txt_history.insert(tk.END, formatted_note + "\n\n")
        self.txt_history.see(tk.END)
        self.txt_history.config(state="disabled")

        messagebox.showinfo("Success", f"Note appended to Patient #{self.cur_selected_id}.")

    # --- UPDATED TREEVIEW WITH FILTERING ---
    def populate_doctor_table(self, f_id="", f_sex="All", f_diag="All"):
        ages = self.enc_columns_ckks['age'].decrypt()
        bps = self.enc_columns_ckks['trestbps'].decrypt()
        chols = self.enc_columns_ckks['chol'].decrypt()
        nums = self.enc_columns_ckks['num'].decrypt()

        grouped_records = {}
        for i in range(len(self.plain_columns['id'])):
            p_id = self.plain_columns['id'][i]
            sex = self.plain_columns['sex'][i]
            diag = "Positive" if nums[i] > 0.5 else "Negative"

            # --- APPLY FILTERS ---
            if f_id and str(p_id) != f_id: continue
            if f_sex != "All" and sex != f_sex: continue
            if f_diag != "All" and diag != f_diag: continue

            record = (
            self.plain_columns['date'][i], p_id, sex, self.plain_columns['dataset'][i], round(bps[i]), round(chols[i]),
            diag)
            if p_id not in grouped_records: grouped_records[p_id] = []
            grouped_records[p_id].append(record)

        def update_ui():
            self.tree.delete(*self.tree.get_children())
            for p_id, visits in grouped_records.items():
                visits.sort(key=lambda x: x[0], reverse=True)
                parent_node = self.tree.insert("", "end", text="➕", values=visits[0], open=False)
                for older_visit in visits[1:]:
                    child_record = list(older_visit)
                    child_record[0] = f" ↳ {child_record[0]}"
                    self.tree.insert(parent_node, "end", text="", values=tuple(child_record))

        self.root.after(0, update_ui)

    def run_he_benchmark(self):
        metric = self.metric_choice.get()
        algo = self.algo_choice.get()
        total_visits = len(self.plain_columns['id'])

        self.res_lab.config(text="Calculating...", fg="orange")
        self.root.update()  # Force UI refresh

        start_time = time.time()

        if "CKKS" in algo:
            enc_vec = self.enc_columns_ckks[metric]
            enc_average = enc_vec.sum() * (1 / total_visits)
            final_answer = enc_average.decrypt()[0]

        elif "BFV" in algo:
            enc_vec = self.enc_columns_bfv[metric]
            enc_sum = enc_vec.sum()
            decrypted_sum = enc_sum.decrypt()[0]
            final_answer = decrypted_sum / total_visits

        execution_time = (time.time() - start_time) * 1000

        # Update UI
        if metric == 'num':
            self.res_lab.config(text=f"Global Prevalence: {final_answer * 100:.2f}%", fg="#2980b9")
        else:
            self.res_lab.config(text=f"Global Avg {metric.upper()}: {final_answer:.2f}", fg="#2980b9")

        self.time_lab.config(text=f"Execution Time: {execution_time:.2f} ms")


if __name__ == "__main__":
    root = tk.Tk()
    app = PureHEMedicalApp(root)
    root.mainloop()