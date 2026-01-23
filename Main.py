import pandas as pd
import numpy as np
import tenseal as ts

MEDICAL_FILE_NAME = "heart_disease_uci.csv"
TARGET_COLUMN = "age"
COUNT_COLUMN = "num"

context = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[60, 40, 40, 60]
)
context.generate_galois_keys()
context.global_scale = 2 ** 40


def load_and_extract_data(filename, avg_column, count_column):
    try:
        df = pd.read_csv(filename, na_values=['?'])
    except FileNotFoundError:
        raise FileNotFoundError(f"Error: Medical data file '{filename}' not found. Please check the file name.")

    df_cleaned = df.dropna(subset=[avg_column, count_column])

    avg_data = df_cleaned[avg_column].to_numpy(dtype=np.float64)

    count_data = (df_cleaned[count_column] > 0).astype(int).to_numpy(dtype=np.float64)

    total_records = len(df_cleaned)

    return avg_data, count_data, total_records


def perform_secure_medical_stats():
    print("=" * 70)
    print("Secure Homomorphic Medical Data Analysis")
    print("=" * 70)

    try:
        age_vector, target_vector, total_records = load_and_extract_data(
            MEDICAL_FILE_NAME, TARGET_COLUMN, COUNT_COLUMN
        )
    except Exception as e:
        print(f"Failed to load data: {e}")
        return

    if total_records == 0:
        print("No valid records found in the dataset.")
        return

    print(f"Total Patient Records Analyzed: {total_records}")

    actual_avg_age = np.mean(age_vector)
    actual_disease_count = np.sum(target_vector)

    ctxt_age = ts.ckks_vector(context, age_vector.tolist())
    ctxt_target = ts.ckks_vector(context, target_vector.tolist())

    print("\nEncryption complete. All individuhal patient data is now secure.")


    ctxt_disease_count = ctxt_target.sum()

    average_scalar = 1 / total_records
    ctxt_age_sum = ctxt_age.sum()
    ctxt_average_age = ctxt_age_sum * average_scalar


    decrypted_count_vector = ctxt_disease_count.decrypt()
    decrypted_disease_count = round(decrypted_count_vector[0])

    decrypted_avg_vector = ctxt_average_age.decrypt()
    decrypted_average_age = decrypted_avg_vector[0]

    print("\n--- SECURE ANALYTICS RESULTS ---")

    print(f"Actual Disease Count:       {actual_disease_count:.0f}")
    print(f"Decrypted Disease Count:    {decrypted_disease_count:.0f} (SUCCESS)")

    print(f"\nActual Average Age:         {actual_avg_age:.2f} years")
    print(f"Decrypted Average Age:      {decrypted_average_age:.2f} years (SUCCESS)")

    print("---------------------------------------------")


# --- Execution ---
if __name__ == "__main__":
    perform_secure_medical_stats()