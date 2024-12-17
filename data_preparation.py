import pandas as pd
import glob
import os
import re
import gc

from src import *

benign_filenames = glob.glob(os.path.join(DATA_DIR, "labelled", "normal", "*.csv"))
iot_devices = list(
    set([re.search(r"([a-zA-Z\-]+)-([0-9]+)", f).group(0) for f in benign_filenames])
)

for iot_device in iot_devices:
    # Get the list of file paths for normal and malicious data for the device
    m_filenames = glob.glob(
        os.path.join(DATA_DIR, "labelled", "malicious", "*", f"{iot_device}*.csv")
    )
    b_filenames = glob.glob(
        os.path.join(DATA_DIR, "labelled", "normal", f"{iot_device}*.csv")
    )

    # Read and concatenate the chunks from all the files associated with the device
    processed_chunks = []
    for filename in b_filenames + m_filenames:
        # Read each file in chunks to optimize memory usage
        for chunk in pd.read_csv(filename, sep="\t", low_memory=False, chunksize=10000):
            processed_chunks.append(chunk)

    if processed_chunks == []:
        continue

    # Concatenate all the chunks into a single DataFrame
    df = pd.concat(processed_chunks)

    output_dir = os.path.join(DATA_DIR, "ready")
    os.makedirs(output_dir, exist_ok=True)

    df.to_csv(os.path.join(output_dir, f"{iot_device}.csv"), index=False)

    # Free up memory by deleting the DataFrames and forcing garbage collection
    del df
    gc.collect()

    print(f"IoT Device: {iot_device} Done!")
