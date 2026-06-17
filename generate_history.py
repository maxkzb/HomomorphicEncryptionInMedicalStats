import pandas as pd
import random
from datetime import datetime, timedelta


def generate_realistic_dataset():
    input_file = 'heart_disease_uci.csv'
    output_file = 'heart_disease_longitudinal.csv'

    try:
        df = pd.read_csv(input_file)
    except FileNotFoundError:
        print(f"Error: Could not find {input_file}. Make sure it is in the same folder.")
        return

    # Date range limits (Jan 1, 2021 to Dec 31, 2023)
    start_date = datetime(2021, 1, 1)
    end_date = datetime(2023, 12, 31)
    total_days_range = (end_date - start_date).days

    expanded_records = []

    print("🧬 Generating longitudinal patient histories...")

    for index, row in df.iterrows():
        # Randomly assign 1, 2, or 3 visits to a patient (mostly 1 or 2)
        num_visits = random.choices([1, 2, 3], weights=[0.6, 0.3, 0.1])[0]

        # Pick a random starting date for their first visit
        random_start_offset = random.randint(0, total_days_range - 365)  # Leave room for future visits
        current_visit_date = start_date + timedelta(days=random_start_offset)

        for visit_num in range(num_visits):
            new_row = row.copy()
            new_row['date'] = current_visit_date.strftime('%Y-%m-%d')

            # For 2nd and 3rd visits, add some realistic biological fluctuation
            if visit_num > 0:
                # Tweak Blood Pressure by -10 to +10
                if pd.notna(new_row['trestbps']) and isinstance(new_row['trestbps'], (int, float)):
                    new_row['trestbps'] += random.randint(-10, 10)

                # Tweak Cholesterol by -15 to +15
                if pd.notna(new_row['chol']) and isinstance(new_row['chol'], (int, float)):
                    new_row['chol'] += random.randint(-15, 15)

            expanded_records.append(new_row)

            # Advance the clock by 2 to 8 months for their next visit
            days_until_next_visit = random.randint(60, 240)
            current_visit_date += timedelta(days=days_until_next_visit)

    # Convert back to a DataFrame
    new_df = pd.DataFrame(expanded_records)

    # Reorder columns so 'date' is right next to 'id'
    cols = new_df.columns.tolist()
    cols.insert(1, cols.pop(cols.index('date')))
    new_df = new_df[cols]

    # Save the new dataset
    new_df.to_csv(output_file, index=False)
    print(f"✅ Success! Created '{output_file}' with {len(new_df)} total clinical visits.")


if __name__ == "__main__":
    generate_realistic_dataset()