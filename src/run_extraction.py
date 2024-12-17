import os
import re

from src.helpers.feature_extractor import PCAPReader
from src.helpers.utils import load_json_file
from src import *


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
                    # Normal traffic does not have subfolders
                    output_subdir = output_dir

                os.makedirs(output_subdir, exist_ok=True)

                # Set output file path in the correct subdirectory
                output_file = os.path.join(output_subdir, file.replace(".pcap", ".csv"))

                normal_metadata_path = os.path.join(
                    METADATA_DIR, "metadata-normal.json"
                )
                normal_metadata = load_json_file(normal_metadata_path)

                match = re.match(r"([a-zA-Z\-]+)-([0-9]+)", file)
                device_name, device_number_str = match.group(1), match.group(2)
                device_number = int(device_number_str) - 1
                device_info = normal_metadata.get(device_name, [])
                device_ip_address = device_info.get("device_ip", [])[device_number]

                filters = f"ip.addr == {device_ip_address}"

                pcapreader = PCAPReader(
                    pcap_path=pcap_file,
                    feature_vector=features,
                    tool=None,
                    tshark_path="tshark",
                    zeek_path=None,
                    filters=filters,
                )
                pcapreader.to_csv(output_file)


if __name__ == "__main__":
    # Input directories
    normal_dir = os.path.join(DATA_DIR, "raw", "normal")
    malicious_dir = os.path.join(DATA_DIR, "raw", "malicious")

    # Output directories
    output_dir_normal = os.path.join(DATA_DIR, "extracted_features", "normal")
    output_dir_malicious = os.path.join(DATA_DIR, "extracted_features", "malicious")

    # Ensure output directories exist
    os.makedirs(output_dir_normal, exist_ok=True)
    os.makedirs(output_dir_malicious, exist_ok=True)

    # Load features
    feature_config = load_json_file("./features/protocol_fields_output_final.json")
    features_to_extract = feature_config["features"]
    features = [feature["field"] for feature in features_to_extract]

    # Process normal traffic
    process_pcap_directory(
        input_dir=normal_dir,
        output_dir=output_dir_normal,
        features=features,
        is_malicious=False,
    )

    # Process malicious traffic
    process_pcap_directory(
        input_dir=malicious_dir,
        output_dir=output_dir_malicious,
        features=features,
        is_malicious=True,
    )
