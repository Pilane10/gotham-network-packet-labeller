# IoT Dataset Processing Pipeline

This repository contains a pipeline for processing IoT network traffic datasets, including **feature extraction**, **feature cleaning**, and **data labelling**. The pipeline is designed for extensibility and reproducibility.

---

## **Table of Contents**
1. [Requirements](#requirements)
2. [Folder Structure](#folder-structure)
3. [Pipeline Tasks](#pipeline-tasks)
4. [Usage](#usage)

---

## **Requirements**

Before running the pipeline, ensure you have the following installed:

- **Python 3.8+**
- Required Python packages (install using `requirements.txt`):
    ```bash
    pip install -r requirements.txt
    ```
- Make (for managing the pipeline tasks).


## **Folder Structure**

The pipeline expects the following directory structure:
```
    ├── bash_scripts/
    ├── data/
    │   ├── raw/                     # Raw network traffic data (input)
    │   ├── extracted_features/      # Extracted features (output from feature extraction)
    │   ├── cleaned_features/        # Cleaned features (output from feature cleaning)
    │   └── labeled_data/            # Labeled data (output from labelling)
    ├── features/
    ├── images/
    ├── metadata/
    ├── notebooks/
    ├── scripts/
    │   ├── run_cleaning.py
    │   ├── run_extraction.py
    │   └── run_labelling.py
    ├── src/
    │   ├── __init__.py
    │   ├── feature_cleaner.py
    │   ├── feature_extractor.py
    │   ├── labeller.py
    │   └── utils.py
    ├── venv/
    ├── .dockerignore
    ├── .gitignore
    ├── Dockerfile
    ├── Makefile
    ├── README.md
    └── requirements.txt
```

## **Pipeline Tasks**

The pipeline is divided into the following stages:

1. **Feature Extraction:** Converts raw network traffic data (e.g., pcap files) into feature datasets.
2. **Feature Cleaning:** Cleans and processes extracted features to ensure consistency.
3. **Data Labelling:** Labels the cleaned datasets with attack and benign traffic labels.
4. **Full Pipeline:** Executes all steps sequentially.

## **Usage**

### **Running Individual Steps**

You can run each stage of the pipeline individually using the Makefile. This allows you to perform specific steps as needed:

- Feature Extraction:
    ``` bash
        make extract_features
    ```
    This will extract features from raw network traffic data.

- Feature Cleaning:
    ``` bash
        make clean_features
    ```
    This will clean and preprocess the extracted feature datasets.

- Data Labelling:
    ``` bash
        make label_data
    ```
    This will label the cleaned datasets with appropriate attack/benign classifications.

### **Running the Full Pipeline**

To run all stages in sequence, execute the following command:
```bash
    pip install -r requirements.txt
```

This will run feature extraction, feature cleaning, and data labelling one after the other, automating the entire pipeline.