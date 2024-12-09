import os
import json
from src.feature_extractor import PCAPReader
from src.utils import load_json_file

def process_pcap_directory(input_dir, output_dir, features, is_malicious=False):
    for root, _, files in os.walk(input_dir):
        for file in files:
            if file.endswith(".pcap"):
                pcap_file = os.path.join(root, file)

                # For malicious traffic, handle subfolder structure
                if is_malicious:
                    # Compute the relative path from the base directory (e.g., "malicious_dir")
                    rel_dir = os.path.relpath(root, input_dir)
    
                    # Correct output directory path by appending the relative directory structure
                    output_subdir = os.path.join(output_dir, rel_dir)
                else:
                    output_subdir = output_dir  # Normal traffic does not have subfolders

                os.makedirs(output_subdir, exist_ok=True)

                # Set output file path in the correct subdirectory
                output_file = os.path.join(output_subdir, file.replace(".pcap", ".csv"))
                
                print(pcap_file)
                pcapreader = PCAPReader(pcap_file, features, None, "tshark", None)
                pcapreader.to_csv(output_file)


if __name__ == "__main__":
    # Input directories
    normal_dir = "../data/raw/normal/"
    malicious_dir = "../data/raw/malicious/"

    # Output directories
    output_dir_normal = "../data/extracted_features/normal/"
    output_dir_malicious = "../data/extracted_features/malicious/"

    # Ensure output directories exist
    os.makedirs(output_dir_normal, exist_ok=True)
    os.makedirs(output_dir_malicious, exist_ok=True)

    # Load features
    feature_config = load_json_file("../features/protocol_fields_output.json")
    features_to_extract = feature_config['features']
    features = [feature['field'] for feature in features_to_extract]

    # Process normal traffic
    process_pcap_directory(
        input_dir=normal_dir,
        output_dir=output_dir_normal,
        features=features,
        is_malicious=False
    )

    # Process malicious traffic
    process_pcap_directory(
        input_dir=malicious_dir,
        output_dir=output_dir_malicious,
        features=features,
        is_malicious=True
    )
