import csv
import json
import os

def convert_csv_to_json(csv_input_filepath, json_output_filepath):
    """Converts a CSV file to a JSON array of objects, skipping empty rows."""
    data = []
    
    try:
        # Using 'latin-1' encoding to successfully read the Windows-exported CSV
        with open(csv_input_filepath, mode='r', encoding='latin-1') as file: 
            csv_reader = csv.DictReader(file)
            for row in csv_reader:
                # 1. Strip whitespace from keys and filter out empty values/columns
                cleaned_row = {k.strip(): v for k, v in row.items() if k.strip() and v}
                
                # 2. Check if the resulting dictionary is empty before appending <- NEW
                if cleaned_row:
                    data.append(cleaned_row)
    except FileNotFoundError:
        print(f"Error: Input CSV file not found at {csv_input_filepath}")
        return

    try:
        with open(json_output_filepath, mode='w', encoding='utf-8') as file:
            json.dump(data, file, indent=2) 
        print(f"\n✅ Success: Conversion complete. JSON file saved to: {json_output_filepath}")
    except Exception as e:
        print(f"Error writing JSON file: {e}")

# --- Execution ---
INPUT_CSV = 'Product Listing.csv'
OUTPUT_JSON = 'static/data/products.json'

convert_csv_to_json(INPUT_CSV, OUTPUT_JSON)