import os
import re
import gc
import glob
import pandas as pd

from src.helpers.feature_cleaner import FeatureCleaner
from src import *


def process_local_datasets(iot_devices):
    """
    Process and clean datasets for a list of IoT devices by reading feature files,
    cleaning them, and consolidating feature information for each device.

    Parameters:
        iot_devices (list): A list of IoT device identifiers to process.

    Returns:
        list: A list of sets representing the features for each device.
    """
    feature_info = []

    # Iterate over each IoT device
    for iot_device in iot_devices:
        # Get the list of file paths for benign and malicious data for the device
        m_filenames = glob.glob(
            os.path.join(
                DATA_DIR, "extracted_features", "malicious", "*", f"{iot_device}*.csv"
            )
        )
        b_filenames = glob.glob(
            os.path.join(DATA_DIR, "extracted_features", "benign", f"{iot_device}*.csv")
        )

        # Read and concatenate the chunks from all the files associated with the device
        processed_chunks = []
        for filename in b_filenames + m_filenames:
            # Read each file in chunks to optimize memory usage
            for chunk in pd.read_csv(
                filename, sep="\t", low_memory=False, chunksize=10000
            ):
                processed_chunks.append(chunk)

        if processed_chunks == []:
            continue

        # Concatenate all the chunks into a single DataFrame
        df = pd.concat(processed_chunks)

        # Perform local cleaning (e.g., handling missing values, transforming features, etc.)
        feature_cleaner = FeatureCleaner()
        df_cleaned = feature_cleaner.clean_features(df)

        # Track the columns (features) in the cleaned data for this IoT device
        feature_info.append(set(df_cleaned.columns))

        # Free up memory by deleting the DataFrames and forcing garbage collection
        del df
        del df_cleaned
        gc.collect()

        print(f"IoT Device: {iot_device} Done!")

    return feature_info


def federated_feature_consolidation(feature_info):
    """
    Consolidate features across all devices by taking the union of features
    from each device to ensure global consistency of features.

    Parameters:
        feature_info (list): A list of sets representing features for each IoT device.

    Returns:
        list: A consolidated list of global features that are common across all devices.
    """
    # Intersect features across all devices to ensure global consistency
    global_features = set.union(*feature_info)
    return list(global_features)


def apply_global_features(cleaned_data, global_features):
    """
    Apply the global set of features to the cleaned data of each device.

    Parameters:
        cleaned_data (dict): A dictionary where keys are device names and values are DataFrames
                             containing the cleaned feature data for each device.
        global_features (list): A list of globally consistent feature names.

    Returns:
        dict: A dictionary with cleaned data for each device, containing only the global features.
    """
    for device, df_cleaned in cleaned_data.items():
        # Select only the columns that are part of the global feature set
        cleaned_data[device] = df_cleaned[global_features]
    return cleaned_data


def save_cleaned_data(cleaned_data, output_dir):
    """
    Save the cleaned data of each IoT device to CSV files in the specified output directory.

    Parameters:
        cleaned_data (dict): A dictionary where keys are device names and values are DataFrames
                             containing the cleaned feature data for each device.
        output_dir (str): The directory where the cleaned data CSV files will be saved.
    """
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Save each device's cleaned data as a CSV file
    for device, df in cleaned_data.items():
        df.to_csv(os.path.join(output_dir, f"{device}_cleaned.csv"), index=False)


if __name__ == "__main__":
    # Define paths to local datasets
    benign_filenames = os.path.join(DATA_DIR, "extracted_features", "benign", "*.csv")
    iot_devices = list(
        set(
            [re.search(r"([a-zA-Z\-]+)-([0-9]+)", f).group(0) for f in benign_filenames]
        )
    )

    # Step 1: Process each device's dataset locally
    feature_info = process_local_datasets(iot_devices)

    # Step 2: Consolidate features across all devices
    m_global_features = federated_feature_consolidation(feature_info)
