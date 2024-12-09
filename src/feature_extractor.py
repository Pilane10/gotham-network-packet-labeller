import subprocess
import pandas as pd


class PCAPReader:
    def __init__(self, pcap_path, feature_vector, tool, tshark_path, zeek_path):
        """
        Initializes the feature extraction process.

        Parameters:
            pcap_path (str): Path to the input pcap file.
            features (list): List of features/fields to extract.
            tshark_path (str): Path to the tshark executable (default is 'tshark').
        """
        self.pcap_path = pcap_path
        self.feature_vector = feature_vector
        self.tool = tool
        self.tshark_path = tshark_path
        self.zeek_path = zeek_path
        self.dataframe = None  # Will store the extracted DataFrame
        
    def to_dataframe(self):
        """
        Extracts features from the pcap file and returns them as a DataFrame.
        
        Returns:
            pd.DataFrame: DataFrame containing the extracted features.
        """
        fields = []
        for feature in self.feature_vector:
            fields += ["-e", feature]

        tshark_command = [
            self.tshark_path,
            "-n",                     # No DNS resolution (speeds up processing)
            "-r", self.pcap_path,     # Input pcap file
            "-T", "fields",           # Output in field format
            *fields,                  # Include all requested fields
            '-E', 'header=y',         # Add column headers
            "-E", "separator=\t",     # Use Tab as CSV delimiter
            '-E', 'occurrence=f',     # First occurrence of repeated fields
        ]
        
        try:
            # Run the tshark command and capture the output
            result = subprocess.run(tshark_command, capture_output=True, text=True, check=True)
            
            # Convert the output to a list of lists
            data = [line.split("\t") for line in result.stdout.strip().split("\n")]
            
            # Create a DataFrame from the data
            self.dataframe = pd.DataFrame(data, columns=self.feature_vector)
            return self.dataframe
        
        except subprocess.CalledProcessError as e:
            print(f"Error executing tshark: {e}")
            print("Ensure that tshark is correctly installed and accessible from the specified path.")
            return None

    def to_csv(self, output_file):
        """
        Saves the extracted features DataFrame to a CSV file.

        Parameters:
            output_csv (str): Path to save the CSV file.
        """
        fields = []
        for feature in self.feature_vector:
            fields += ["-e", feature]

        tshark_command = [
            self.tshark_path,
            "-n",                     # No DNS resolution (speeds up processing)
            "-r", self.pcap_path,     # Input pcap file
            "-T", "fields",           # Output in field format
            *fields,                  # Include all requested fields
            '-E', 'header=y',         # Add column headers
            "-E", "separator=\t",     # Use Tab as CSV delimiter
            '-E', 'occurrence=f',     # First occurrence of repeated fields
        ]
        
        try:
            with open(output_file, 'w') as out:
                subprocess.run(tshark_command, stdout=out)

            print(f"tshark parsing complete. File saved as: {output_file}")
        except subprocess.CalledProcessError as e:
            print(f"Error executing tshark: {e}")
            print("Ensure that tshark is correctly installed and accessible from the specified path.")
            return None