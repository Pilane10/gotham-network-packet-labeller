# src/pipeline.py

import os
import pandas as pd
from src.labeller import Labeller
from src.utils import load_json_file


def run_pipeline(csv_directory, output_directory, normal_metadata_path, malicious_metadata_path):
    
    # Load metadata for normal and malicious rules
    normal_metadata = load_json_file(normal_metadata_path)
    malicious_metadata = load_json_file(malicious_metadata_path)

    # Loop through each CSV file in the specified directory
    for filename in os.listdir(csv_directory):
        if filename.endswith(".csv"):
            csv_file_path = os.path.join(csv_directory, filename)

            # Load packet data
            df = pd.read_csv(csv_file_path, sep=";", low_memory=False)

            # Initialize Labeler with metadata
            labeller = Labeller(
                normal_metadata=normal_metadata,
                malicious_metadata=malicious_metadata,
            )

            # Label the data
            labeled_df = labeller.label_data(filename, df)

            # Save labeled data
            output_file = os.path.join(output_directory, filename)
            labeled_df.to_csv(output_file, index=False, sep=";")
            print(f"Labeled data saved to {output_file}")


# Example execution
if __name__ == "__main__":
    malicious_event_type = input("Enter the type of malicious event (e.g., 'masscan'): ")

    csv_directory = f'data/extracted_features/malicious/{malicious_event_type}/'
    output_directory = os.path.join("data", "labelled", "malicious", malicious_event_type)
    normal_metadata_path = os.path.join("metadata", "metadata-normal.json")
    malicious_metadata_path = os.path.join("metadata", f"metadata-{malicious_event_type}.json")

    os.makedirs(output_directory, exist_ok=True)  # Ensure output directory exists

    run_pipeline(
        csv_directory=csv_directory,
        output_directory=output_directory,
        normal_metadata_path=normal_metadata_path,
        malicious_metadata_path=malicious_metadata_path
    )
