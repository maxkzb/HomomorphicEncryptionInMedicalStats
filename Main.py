import pandas as pd
import numpy as np
import tenseal as ts
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[60, 40, 40, 60]
)
context.generate_galois_keys()
context.global_scale = 2 ** 40


class MedicalDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Medical Data Manager")
        self.root.geometry("1000x700")

        self.FILENAME = "heart_disease_uci.csv"
        self.df = self.load_data()

        self.setup_layout()

    def load_data(self):
        try:
            df = pd.read_csv(self.FILENAME, na_values=['?'])
            df['age'] = pd.to_numeric(df['age'], errors='coerce').fillna(df['age'].median())
            df['num'] = pd.to_numeric(df['num'], errors='coerce').fillna(0)
            return df
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load {self.FILENAME}\n{e}")
            return pd.DataFrame()

    def setup_layout(self):
        header = tk.Frame(self.root, bg="#2c3e50", height=60)
        header.pack(fill="x")
        tk.Label(header, text="Medical Records & Privacy-Preserving Analytics",
                 fg="white", bg="#2c3e50", font=("Helvetica", 16, "bold")).pack(pady=15)

        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        list_frame = tk.LabelFrame(main_frame, text="Patient Database", font=("Helvetica", 10, "bold"))
        list_frame.pack(side="left", fill="both", expand=True, padx=5)

        self.tree = ttk.Treeview(list_frame, columns=("ID", "Age", "Sex", "Clinic"), show='headings')
        self.tree.heading("ID", text="Patient ID")
        self.tree.heading("Age", text="Age")
        self.tree.heading("Sex", text="Gender")
        self.tree.heading("Clinic", text="Clinic")
        self.tree.column("ID", width=70)
        self.tree.column("Age", width=50)

        scb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scb.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scb.pack(side="right", fill="y")

        for _, row in self.df.iterrows():
            self.tree.insert("", "end", values=(int(row['id']), int(row['age']), row['sex'], row['dataset']))

        self.tree.bind("<<TreeviewSelect>>", self.on_patient_select)

        right_frame = tk.Frame(main_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=5)

        self.detail_frame = tk.LabelFrame(right_frame, text="Patient Record Detail", font=("Helvetica", 10, "bold"),
                                          padx=10, pady=10)
        self.detail_frame.pack(fill="x", pady=5)

        self.detail_label = tk.Label(self.detail_frame, text="Select a patient from the list to view results.",
                                     justify="left", font=("Helvetica", 11), wraplength=400)
        self.detail_label.pack(anchor="w")

        stats_frame = tk.LabelFrame(right_frame, text="Homomorphic Global Analytics", font=("Helvetica", 10, "bold"),
                                    padx=10, pady=10)
        stats_frame.pack(fill="both", expand=True, pady=5)

        tk.Label(stats_frame, text="Perform system-wide statistics across all encrypted records.",
                 font=("Helvetica", 9, "italic")).pack(pady=5)

        self.btn_he = tk.Button(stats_frame, text="🚀 Run Secure Global Stats", command=self.run_he_thread,
                                bg="#16a085", fg="white", font=("Helvetica", 11, "bold"), pady=10)
        self.btn_he.pack(fill="x", pady=10)

        self.progress = ttk.Progressbar(stats_frame, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(fill="x", pady=5)

        self.status_label = tk.Label(stats_frame, text="Status: Ready", fg="gray")
        self.status_label.pack()

        self.stats_result_label = tk.Label(stats_frame, text="", font=("Courier", 10), justify="left", bg="#ecf0f1",
                                           relief="sunken", pady=10)
        self.stats_result_label.pack(fill="both", expand=True, pady=10)

    def on_patient_select(self, event):
        selected_item = self.tree.selection()[0]
        p_id = self.tree.item(selected_item)['values'][0]

        row = self.df[self.df['id'] == p_id].iloc[0]

        diagnosis = "Positive (Heart Issues)" if row['num'] > 0 else "Negative (Normal)"

        detail_text = (
            f"IDENTIFIER:  Patient #{int(row['id'])}\n"
            f"DEMOGRAPHICS: {row['age']} yr old {row['sex']}\n"
            f"CLINIC:      {row['dataset']}\n"
            f"BP/CHOL:     {row['trestbps']} mmHg / {row['chol']} mg/dL\n"
            f"----------------------------------\n"
            f"DIAGNOSIS:   {diagnosis}"
        )
        self.detail_label.config(text=detail_text, fg="#2980b9" if row['num'] == 0 else "#c0392b")

    def run_he_thread(self):
        self.btn_he.config(state="disabled")
        threading.Thread(target=self.perform_he, daemon=True).start()

    def perform_he(self):
        try:
            self.status_label.config(text="Status: Encrypting 920 records...", fg="#e67e22")
            self.progress['value'] = 20
            time.sleep(1)

            ages = self.df['age'].tolist()
            disease = (self.df['num'] > 0).astype(float).tolist()

            enc_ages = ts.ckks_vector(context, ages)
            enc_disease = ts.ckks_vector(context, disease)

            self.progress['value'] = 60
            self.status_label.config(text="Status: Computing on Ciphertext...", fg="#e67e22")
            time.sleep(1.2)

            enc_avg_age = enc_ages.sum() * (1 / len(ages))
            enc_total_disease = enc_disease.sum()

            self.progress['value'] = 90
            self.status_label.config(text="Status: Decrypting results...", fg="#e67e22")
            time.sleep(0.8)

            avg_age = enc_avg_age.decrypt()[0]
            total_disease = round(enc_total_disease.decrypt()[0])

            self.progress['value'] = 100
            self.status_label.config(text="Status: Analysis Complete", fg="green")

            result_text = (
                f"=== GLOBAL HE RESULTS ===\n"
                f"Total Population: {len(self.df)}\n"
                f"Average Age:      {avg_age:.2f} yrs\n"
                f"Total Diagnosed:  {total_disease}\n"
                f"Prevalence:       {(total_disease / len(self.df)) * 100:.1f}%\n"
                f"=========================="
            )
            self.stats_result_label.config(text=result_text)
            messagebox.showinfo("Success", "Homomorphic computation finished securely.")

        except Exception as e:
            messagebox.showerror("HE Error", str(e))
        finally:
            self.btn_he.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    app = MedicalDashboard(root)
    root.mainloop()