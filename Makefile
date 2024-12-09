# Define variables for directories and scripts
EXTRACT_SCRIPT = ./scripts/run_extraction.py
CLEAN_SCRIPT = ./scripts/run_cleaning.py
LABEL_SCRIPT = ./scripts/run_labelling.py

# Phony targets (tasks that don't correspond to file names)
.PHONY: extract_features clean_features label_data run_pipeline

# Feature extraction
extract_features:
	@echo "Running feature extraction..."
	python3 $(EXTRACT_SCRIPT)

# Feature cleaning
clean_features: extract_features
	@echo "Running feature cleaning..."
	python3 $(CLEAN_SCRIPT)

# Labelling
label_data: clean_features
	@echo "Running labelling..."
	python3 $(LABEL_SCRIPT)

# Run all steps of the pipeline
run_pipeline: extract_features clean_features label_data
	@echo "Pipeline completed!"
