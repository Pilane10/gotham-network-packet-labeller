# src/pipeline.py

import os
import pandas as pd

from src.helpers.labeller import Labeller
from src.helpers.utils import load_json_file
from src import *


def run_pipeline(
    csv_directory,
    output_directory,
    benign_metadata_path,
    malicious_metadata_path,
    is_malicious=True,
):
    # Load metadata for benign and malicious rules
    benign_metadata = load_json_file(benign_metadata_path)
    if malicious_metadata_path:
        malicious_metadata = load_json_file(malicious_metadata_path)
    else:
        malicious_metadata = []

    # Initialize Labeler with metadata
    labeller = Labeller(
        benign_metadata=benign_metadata,
        malicious_metadata=malicious_metadata,
    )

    # Loop through each CSV file in the specified directory
    for filename in os.listdir(csv_directory):
        if filename.endswith(".csv"):
            csv_file_path = os.path.join(csv_directory, filename)

            # Load packet data
            df = pd.read_csv(csv_file_path, sep="\t", low_memory=False)

            # Label the data
            labeled_df = labeller.label_data(filename, df)

            # Save labeled data
            output_file = os.path.join(output_directory, filename)
            labeled_df.to_csv(output_file, index=False, sep="\t")
            print(f"Labeled data saved to {output_file}")


# Example execution
if __name__ == "__main__":
    benign_metadata_path = os.path.join(METADATA_DIR, "metadata-benign.json")
    for event in EVENTS:
        if event == "benign":
            csv_directory = os.path.join(DATA_DIR, "extracted_features", "benign")
            output_directory = os.path.join(DATA_DIR, "labelled", "benign")
            malicious_metadata_path = None
            is_malicious = False
        else:
            csv_directory = os.path.join(
                DATA_DIR, "extracted_features", "malicious", event
            )
            output_directory = os.path.join(DATA_DIR, "labelled", "malicious", event)
            malicious_metadata_path = os.path.join(
                METADATA_DIR, f"metadata-{event}.json"
            )
            is_malicious = True

        os.makedirs(output_directory, exist_ok=True)  # Ensure output directory exists

        # Label traffic
        run_pipeline(
            csv_directory=csv_directory,
            output_directory=output_directory,
            benign_metadata_path=benign_metadata_path,
            malicious_metadata_path=malicious_metadata_path,
            is_malicious=is_malicious,
        )
