import pandas as pd
import tenseal as ts
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import os
import pickle
import base64
import hashlib
from simple_keystore import SimpleKeyStore


class PureHEMedicalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Pure HE Vault")
        self.root.geometry("1200x800")

        self.DB_FILE = "he_vectors_only.pkl"
        self.RAW_FILE = "heart_disease_uci.csv"
        self.KEYSTORE_FILE = "he_vault.db"

        self.he_context = None
        self.enc_columns = {}
        self.plain_columns = {}

        self.init_security_and_data()

    def get_keystore_token(self, password):
        """Generates a secure 32-byte token for simple_keystore using only built-in libraries."""
        digest = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8')

    def init_security_and_data(self):
        self.root.withdraw()

        if not os.path.exists(self.KEYSTORE_FILE) or not os.path.exists(self.DB_FILE):
            pwd = simpledialog.askstring("New Keystore", "Create a Master Password:", show='*')
            if not pwd: self.root.destroy(); return

            # Pass the password to simple_keystore
            os.environ['SIMPLE_KEYSTORE_KEY'] = self.get_keystore_token(pwd)

            # Generate HE Context
            context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
            context.generate_galois_keys()
            context.global_scale = 2 ** 40
            self.he_context = context

            # Save Secret Key to Keystore
            ks = SimpleKeyStore(self.KEYSTORE_FILE)
            ks.add_key(name="tenseal_sk", unencrypted_key=context.serialize(save_secret_key=True).hex())

            self.encrypt_raw_to_disk()
            messagebox.showinfo("Setup Complete", "Data homomorphically encrypted.")
        else:
            pwd = simpledialog.askstring("Unlock Keystore", "Enter Master Password:", show='*')
            if not pwd: self.root.destroy(); return

            try:
                os.environ['SIMPLE_KEYSTORE_KEY'] = self.get_keystore_token(pwd)
                ks = SimpleKeyStore(self.KEYSTORE_FILE)
                sk_hex = ks.get_key_by_name("tenseal_sk")
                self.he_context = ts.context_from(bytes.fromhex(sk_hex))
                self.load_he_vectors()
            except Exception as e:
                messagebox.showerror("Auth Failed", "Incorrect Password or Keystore error.")
                self.root.destroy();
                return

        self.root.deiconify()
        self.show_login_panel()

    def encrypt_raw_to_disk(self):
        df = pd.read_csv(self.RAW_FILE, na_values=['?'])
        for col in ['age', 'trestbps', 'chol', 'num']:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

        # PURE HE: Encrypting only with TenSEAL
        enc_bytes_dict = {
            'age': ts.ckks_vector(self.he_context, df['age'].tolist()).serialize(),
            'trestbps': ts.ckks_vector(self.he_context, df['trestbps'].tolist()).serialize(),
            'chol': ts.ckks_vector(self.he_context, df['chol'].tolist()).serialize(),
            'num': ts.ckks_vector(self.he_context, (df['num'] > 0).astype(float).tolist()).serialize()
        }

        plain_dict = {
            'id': df['id'].tolist(),
            'sex': df['sex'].tolist(),
            'dataset': df['dataset'].tolist()
        }

        # Saving the HE vectors to disk directly
        with open(self.DB_FILE, "wb") as f:
            pickle.dump({"enc": enc_bytes_dict, "plain": plain_dict}, f)

        self.load_he_vectors()

    def load_he_vectors(self):
        with open(self.DB_FILE, "rb") as f:
            data = pickle.load(f)
            self.plain_columns = data["plain"]
            self.enc_columns = {
                col: ts.ckks_vector_from(self.he_context, enc_bytes)
                for col, enc_bytes in data["enc"].items()
            }

    def clear_screen(self):
        for widget in self.root.winfo_children(): widget.destroy()

    def show_login_panel(self):
        self.clear_screen()
        self.root.geometry("450x500")
        tk.Label(self.root, text="🛡️ Pure HE Portal", font=("Arial", 24, "bold")).pack(pady=40)

        p_frame = tk.LabelFrame(self.root, text="Patient Access", padx=20, pady=20)
        p_frame.pack(pady=10, fill="x", padx=40)
        tk.Label(p_frame, text="Patient ID:").pack()
        self.p_login_id = tk.Entry(p_frame, justify='center', bg="white", fg="black", insertbackground="black")
        self.p_login_id.pack(pady=10);
        self.p_login_id.insert(0, "1")
        tk.Button(p_frame, text="Decrypt My Record", command=self.auth_patient).pack()

        tk.Label(self.root, text="— OR —", fg="gray").pack(pady=20)

        d_frame = tk.LabelFrame(self.root, text="Medical Staff", padx=20, pady=20)
        d_frame.pack(fill="x", padx=40)
        tk.Button(d_frame, text="Open Doctor Dashboard", command=self.show_doctor_dashboard).pack()

    def auth_patient(self):
        try:
            p_id = int(self.p_login_id.get())
            if p_id in self.plain_columns['id']:
                self.show_patient_view(p_id)
            else:
                messagebox.showerror("Error", "ID not found.")
        except ValueError:
            messagebox.showerror("Error", "Enter numeric ID.")

    def show_patient_view(self, p_id):
        self.clear_screen()
        idx = self.plain_columns['id'].index(p_id)

        tk.Label(self.root, text=f"Record #{p_id}", font=("Helvetica", 18, "bold")).pack(pady=20)
        box = tk.Text(self.root, height=12, width=40, font=("Courier", 12))
        box.pack(pady=10)

        # Decrypting HE vector for patient view
        age = round(self.enc_columns['age'].decrypt()[idx])
        bp = round(self.enc_columns['trestbps'].decrypt()[idx])
        chol = round(self.enc_columns['chol'].decrypt()[idx])
        sick = self.enc_columns['num'].decrypt()[idx] > 0.5

        box.insert(tk.END, f"AGE: {age}\nSEX: {self.plain_columns['sex'][idx]}\n")
        box.insert(tk.END, f"CLINIC: {self.plain_columns['dataset'][idx]}\n")
        box.insert(tk.END, f"BP: {bp}\nCHOL: {chol}\n")
        box.insert(tk.END, f"DIAGNOSIS: {'DISEASE DETECTED' if sick else 'HEALTHY'}")
        box.config(state="disabled")

        tk.Button(self.root, text="Logout", command=self.show_login_panel).pack(pady=20)

    def show_doctor_dashboard(self):
        self.clear_screen()
        self.root.geometry("1200x800")

        header = tk.Frame(self.root, bg="#2c3e50")
        header.pack(fill="x")
        tk.Label(header, text="Doctor's View & HE Analytics", fg="white", bg="#2c3e50", font=("Helvetica", 16)).pack(
            pady=15)

        main = tk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=10, pady=10)

        left = tk.Frame(main)
        left.pack(side="left", fill="both", expand=True)

        cols = ("ID", "Age", "Sex", "Clinic", "BP", "Chol", "Diagnosis")
        self.tree = ttk.Treeview(left, columns=cols, show='headings')
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=80)

        scb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scb.pack(side="right", fill="y")

        threading.Thread(target=self.populate_doctor_table, daemon=True).start()

        right = tk.Frame(main, width=350)
        right.pack(side="right", fill="both", padx=10)
        right.pack_propagate(False)

        he_frame = tk.LabelFrame(right, text="Perform Math on Ciphertext", padx=20, pady=20)
        he_frame.pack(fill="both", expand=True, pady=10)

        self.metric_choice = ttk.Combobox(he_frame, values=["age", "trestbps", "chol", "num (Prevalence)"],
                                          state="readonly")
        self.metric_choice.set("age")
        self.metric_choice.pack(pady=10)

        tk.Button(he_frame, text="Calculate Homomorphically", command=self.run_he, bg="#3498db").pack(pady=10)
        self.res_lab = tk.Label(he_frame, text="Result will appear here", font=("Arial", 11, "bold"), fg="blue")
        self.res_lab.pack(pady=20)

        tk.Button(self.root, text="Logout", command=self.show_login_panel).pack(pady=20)

    def populate_doctor_table(self):
        # Decrypt HE vectors to populate the doctor's table view
        ages = self.enc_columns['age'].decrypt()
        bps = self.enc_columns['trestbps'].decrypt()
        chols = self.enc_columns['chol'].decrypt()
        nums = self.enc_columns['num'].decrypt()

        for i in range(len(self.plain_columns['id'])):
            p_id = self.plain_columns['id'][i]
            sex = self.plain_columns['sex'][i]
            clinic = self.plain_columns['dataset'][i]
            diag = "Positive" if nums[i] > 0.5 else "Negative"

            vals = (p_id, round(ages[i]), sex, clinic, round(bps[i]), round(chols[i]), diag)
            self.root.after(0, lambda v=vals: self.tree.insert("", "end", values=v))

    def run_he(self):
        metric = self.metric_choice.get().split()[0]
        enc_vec = self.enc_columns[metric]

        total_patients = len(self.plain_columns['id'])
        # Math is performed on the HE ciphertext
        enc_average = enc_vec.sum() * (1 / total_patients)
        final_answer = enc_average.decrypt()[0]

        if metric == 'num':
            self.res_lab.config(text=f"Global Prevalence: {final_answer * 100:.2f}%")
        else:
            self.res_lab.config(text=f"Global Avg {metric.upper()}: {final_answer:.2f}")


if __name__ == "__main__":
    root = tk.Tk()
    app = PureHEMedicalApp(root)
    root.mainloop()