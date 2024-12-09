import os
import json
from pcap_processor import process_pcap_directory


def main():

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
    with open("../protocol_fields_output_missing_values.json", "r") as file:
        feature_config = json.load(file)

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

if __name__ == "__main__":
    main()
