import os
import glob
import pandas as pd
import gc

from src.helpers.preprocessor import DataPreprocessor
from src import *
from src.config import *


def process_csv_files(input_dir, output_dir, preprocessor):
    # Get list of CSV filenames
    filenames = glob.glob(os.path.join(input_dir, "*.csv"))

    for filename in filenames:
        print(f"Processing {filename}")

        processed_chunks = []  # List to hold processed data chunks

        # Process CSV file in chunks for memory efficiency
        for chunk in pd.read_csv(filename, sep=",", low_memory=False, chunksize=10000):
            chunk = preprocessor.extract_protocols_and_ports(chunk)
            chunk = preprocessor.convert_time(chunk)
            chunk = preprocessor.convert_ports(chunk)
            chunk = preprocessor.convert_checksums(chunk)
            chunk = preprocessor.fill_missing_values(chunk)
            chunk = preprocessor.rename_labels(chunk)
            chunk = preprocessor.group_labels(chunk)
            chunk = preprocessor.select_columns(chunk)

            processed_chunks.append(chunk)

        # Concatenate all processed chunks into a single DataFrame
        df = pd.concat(processed_chunks, ignore_index=True)

        # Split data into training, validation, and testing sets
        training_set, validation_set, testing_set = preprocessor.train_valid_test_split(
            df
        )

        # Scale the data and split into features and labels
        (
            (X_train, y_train_not_grouped, y_train_grouped),
            (X_val, y_val_not_grouped, y_val_grouped),
            (X_test, y_test_not_grouped, y_test_grouped),
        ) = preprocessor.scale(training_set, validation_set, testing_set)

        # Extract IoT device name from filename for saving
        iot_device = os.path.basename(filename).rstrip(".csv")

        # Save the processed data to pickle files for each IoT device
        X_train.to_pickle(
            os.path.join(output_dir, f"{iot_device}_train_features.pkl"),
            compression="gzip",
        )
        y_train_not_grouped.to_pickle(
            os.path.join(output_dir, f"{iot_device}_train_labels.pkl"),
            compression="gzip",
        )
        y_train_grouped.to_pickle(
            os.path.join(output_dir, f"{iot_device}_train_labels_grouped.pkl"),
            compression="gzip",
        )

        X_val.to_pickle(
            os.path.join(output_dir, f"{iot_device}_val_features.pkl"),
            compression="gzip",
        )
        y_val_not_grouped.to_pickle(
            os.path.join(output_dir, f"{iot_device}_val_labels.pkl"), compression="gzip"
        )
        y_val_grouped.to_pickle(
            os.path.join(output_dir, f"{iot_device}_val_labels_grouped.pkl"),
            compression="gzip",
        )

        X_test.to_pickle(
            os.path.join(output_dir, f"{iot_device}_test_features.pkl"),
            compression="gzip",
        )
        y_test_not_grouped.to_pickle(
            os.path.join(output_dir, f"{iot_device}_test_labels.pkl"),
            compression="gzip",
        )
        y_test_grouped.to_pickle(
            os.path.join(output_dir, f"{iot_device}_test_labels_grouped.pkl"),
            compression="gzip",
        )

        # Clean up memory by deleting intermediate variables and performing garbage collection
        del (
            chunk,
            df,
            training_set,
            validation_set,
            testing_set,
            X_train,
            y_train_not_grouped,
            y_train_grouped,
            X_val,
            y_val_not_grouped,
            y_val_grouped,
            X_test,
            y_test_not_grouped,
            y_test_grouped,
        )
        gc.collect()


if __name__ == "__main__":
    # Initialize data preprocessor with global values
    preprocessor = DataPreprocessor(
        port_hierarchy_map_iot=port_hierarchy_map_iot,
        global_categorical_values=global_categorical_values,
        global_label_values=global_label_values,
        global_label_grouped_values=global_label_grouped_values,
    )

    # Define input and output directories
    input_dir = "./data/processed"
    output_dir = os.path.join(DATA_DIR, "final")

    os.makedirs(output_dir, exist_ok=True)  # Ensure output directory exists

    # Process the CSV files
    process_csv_files(input_dir, output_dir, preprocessor)
