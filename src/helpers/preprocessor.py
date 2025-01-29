import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import (
    FunctionTransformer,
    StandardScaler,
    OneHotEncoder,
    LabelEncoder,
)
from sklearn.compose import ColumnTransformer


class DataPreprocessor:
    def __init__(
        self,
        port_hierarchy_map_iot,
        global_categorical_values,
        global_label_values,
        global_label_grouped_values,
        training_size=0.6,
        validation_size=0.2,
        testing_size=0.2,
    ):
        """
        Initialize the DataPreprocessor with required mappings and configurations.

        Parameters:
        port_hierarchy_map_iot (dict): Port hierarchy map for IoT devices.
        global_categorical_values (dict): Global categorical values for encoding.
        global_label_values (list): List of global label values for encoding.
        training_size (float): Proportion of the data to be used for training (default is 0.6).
        validation_size (float): Proportion of the data to be used for validation (default is 0.2).
        testing_size (float): Proportion of the data to be used for testing (default is 0.2).
        """
        self.port_hierarchy_map_iot = port_hierarchy_map_iot
        self.global_categorical_values = global_categorical_values
        self.global_label_values = global_label_values
        self.global_label_grouped_values = global_label_grouped_values
        self.training_size = training_size
        self.validation_size = validation_size
        self.testing_size = testing_size

    def scale(self, training_set, validation_set, testing_set):
        """
        Scale the numerical features and encode categorical features using OneHotEncoder.

        Parameters:
        training_set (tuple): A tuple containing the training features and labels.
        validation_set (tuple): A tuple containing the validation features and labels.
        testing_set (tuple): A tuple containing the testing features and labels.

        Returns:
        tuple: A tuple containing the scaled and encoded training, validation, and testing sets.
        """
        (X_train, y_train), (X_val, y_val), (X_test, y_test) = (
            training_set,
            validation_set,
            testing_set,
        )

        categorical_features = X_train.select_dtypes(exclude=["number"]).columns
        numeric_features = X_train.select_dtypes(exclude=[object]).columns

        preprocessor = ColumnTransformer(
            transformers=[
                (
                    "flags",
                    FunctionTransformer(self.unpack_flags),
                    ["ip.flags", "tcp.flags"],
                ),
                (
                    "categoricals",
                    OneHotEncoder(
                        drop="first", sparse_output=True, handle_unknown="error"
                    ),
                    ["ip.protocol", "src.port", "dst.port"],
                ),
                ("numericals", StandardScaler(), numeric_features),
            ]
        )

        preprocessor.fit(X_train)
        preprocessor["categoricals"].fit(self.global_categorical_values)

        # Preprocess the features
        X_train = pd.DataFrame(preprocessor.transform(X_train))
        X_val = pd.DataFrame(preprocessor.transform(X_val))
        X_test = pd.DataFrame(preprocessor.transform(X_test))

        # Preprocess the labels
        le = LabelEncoder()
        le.fit(self.global_label_values)

        y_train_not_grouped = pd.DataFrame(
            le.transform(y_train["label"]), columns=["label"]
        )
        y_val_not_grouped = pd.DataFrame(
            le.transform(y_val["label"]), columns=["label"]
        )
        y_test_not_grouped = pd.DataFrame(
            le.transform(y_test["label"]), columns=["label"]
        )

        le = LabelEncoder()
        le.fit(self.global_label_grouped_values)

        y_train_grouped = pd.DataFrame(
            le.transform(y_train["label_category"]), columns=["label_category"]
        )
        y_val_grouped = pd.DataFrame(
            le.transform(y_val["label_category"]), columns=["label_category"]
        )
        y_test_grouped = pd.DataFrame(
            le.transform(y_test["label_category"]), columns=["label_category"]
        )

        return (
            (X_train, y_train_not_grouped, y_train_grouped),
            (X_val, y_val_not_grouped, y_val_grouped),
            (X_test, y_test_not_grouped, y_test_grouped),
        )

    def train_valid_test_split(self, df):
        """
        Split the dataset into training, validation, and testing sets.

        Parameters:
        df (pandas.DataFrame): Feature dataset.

        Returns:
        tuple: A tuple containing three tuples (X_train, y_train), (X_val, y_val), (X_test, y_test)
        """
        self.labels = df[["label", "label_category"]]
        self.features = df.drop(labels=["label", "label_category"], axis=1)

        X_train, X_test, y_train, y_test = train_test_split(
            self.features,
            self.labels,
            test_size=(self.validation_size + self.testing_size),
            random_state=42,
            stratify=self.labels,
        )
        X_test, X_val, y_test, y_val = train_test_split(
            X_test,
            y_test,
            test_size=self.testing_size / (self.validation_size + self.testing_size),
            random_state=42,
        )

        return (X_train, y_train), (X_val, y_val), (X_test, y_test)

    @staticmethod
    def extract_protocols_and_ports(df):
        """
        Extract protocol and port information from packet data.

        Parameters:
        df (pandas.DataFrame): Input dataset.

        Returns:
        pandas.DataFrame: Dataset with extracted protocol and port information.
        """
        src_ports, dst_ports, protocols = [], [], []
        for _, pkt in df.iterrows():
            if ":tcp" in pkt["frame.protocols"]:
                protocol = "TCP"
                src_port = int(pkt["tcp.srcport"])
                dst_port = int(pkt["tcp.dstport"])
            elif ":udp" in pkt["frame.protocols"]:
                protocol = "UDP"
                src_port = int(pkt["udp.srcport"])
                dst_port = int(pkt["udp.dstport"])
            elif ":icmp" in pkt["frame.protocols"]:
                protocol = "ICMP"
                src_port = np.nan
                dst_port = np.nan

            protocols.append(protocol)
            src_ports.append(src_port)
            dst_ports.append(dst_port)

        df["ip.protocol"] = protocols
        df["src.port"] = src_ports
        df["dst.port"] = dst_ports

        df.drop(
            columns=[
                "ip.proto",
                "tcp.srcport",
                "tcp.dstport",
                "udp.srcport",
                "udp.dstport",
            ],
            axis=1,
            inplace=True,
        )
        return df

    @staticmethod
    def convert_time(df):
        """
        Convert frame time to Unix timestamp.

        Parameters:
        df (pandas.DataFrame): Input dataset.

        Returns:
        pandas.DataFrame: Dataset with timestamp column.
        """
        df["frame.time"] = df["frame.time"].str.replace("  ", " ")
        df["frame.time"] = df["frame.time"].str.replace(" BST", "")
        df["frame.time"] = df["frame.time"].str.replace(" GMT", "")
        df["frame.time"] = pd.to_datetime(
            df["frame.time"], format="%b %d, %Y %H:%M:%S.%f000"
        )
        df["timestamp"] = df["frame.time"].values.astype(np.int64) // 10**9
        return df

    def convert_ports(self, df):
        """
        Convert ports to categorical values using a predefined port hierarchy.

        Parameters:
        df (pandas.DataFrame): Input dataset.

        Returns:
        pandas.DataFrame: Dataset with converted ports.
        """
        df["src.port"] = df["src.port"].apply(
            lambda port: self.port_to_categories(port)
        )
        df["dst.port"] = df["dst.port"].apply(
            lambda port: self.port_to_categories(port)
        )
        return df

    @staticmethod
    def convert_checksums(df):
        """
        Convert checksum fields to integers, replacing missing values with a default value.

        Parameters:
        df (pandas.DataFrame): Input dataset.

        Returns:
        pandas.DataFrame: Dataset with converted checksum fields.
        """
        df["ip.checksum"] = df["ip.checksum"].apply(
            lambda x: int(str(x), 16) if pd.notna(x) else 0
        )
        df["tcp.checksum"] = df["tcp.checksum"].apply(
            lambda x: int(str(x), 16) if pd.notna(x) else 0
        )
        df["tcp.options"] = (
            df["tcp.options"]
            .apply(lambda x: int(str(x), 16) if pd.notna(x) else 0)
            .astype(float)
        )
        return df

    @staticmethod
    def fill_missing_values(df):
        """
        Fill missing values with a default value (-1).

        Parameters:
        df (pandas.DataFrame): Input dataset.

        Returns:
        pandas.DataFrame: Dataset with missing values filled.
        """
        num_cols = df.select_dtypes(include=["number"]).columns
        df[num_cols] = df[num_cols].fillna(-1)

        cat_cols = df.select_dtypes(exclude=["number"]).columns
        df[cat_cols] = df[cat_cols].fillna(-1)

        return df

    @staticmethod
    def select_columns(df):
        """
        Select relevant columns from the dataset.

        Parameters:
        df (pandas.DataFrame): Input dataset.

        Returns:
        pandas.DataFrame: Dataset with selected columns.
        """
        selected_columns = [
            "timestamp",
            "frame.len",
            "ip.protocol",
            "src.port",
            "dst.port",
            "ip.flags",
            "ip.ttl",
            "ip.checksum",
            "tcp.flags",
            "tcp.window_size_value",
            "tcp.window_size_scalefactor",
            "tcp.checksum",
            "tcp.options",
            "tcp.pdu.size",
            "label",
            "label_category",
        ]

        df = df[selected_columns]
        df = df[df["label"] != "Unknown"]
        return df

    @staticmethod
    def rename_labels(df):
        """
        Rename attack labels to standardized values.
        """
        df["label"] = df["label"].str.replace(
            "^C&C Communication", "Mirai C&C Communication", regex=True
        )
        return df

    @staticmethod
    def group_labels(df):
        """
        Group the attack labels into broader categories.
        """
        attack_group = {
            "Benign": "Benign",
            "TCP Scan": "Network Scanning",
            "UDP Scan": "Network Scanning",
            "Telnet Brute Force": "Brute Force",
            "Reporting": "Infection",
            "Ingress Tool Transfer": "Infection",
            "File Download": "Infection",
            "CoAP Amplification": "DoS",
            "Merlin TCP Flooding": "DoS",
            "Merlin UDP Flooding": "DoS",
            "Merlin ICMP Flooding": "DoS",
            "Merlin C&C Communication": "C&C Communication",
            "Mirai TCP Flooding": "DoS",
            "Mirai UDP Flooding": "DoS",
            "Mirai GRE Flooding": "DoS",
            "Mirai C&C Communication": "C&C Communication",
        }

        # Create grouped label column
        df["label_category"] = df["label"].map(lambda x: attack_group.get(x, "Other"))
        return df

    @staticmethod
    def unpack_flags(X):
        X = X.copy()

        # Unpack IP flags
        ip_flags = X["ip.flags"].apply(lambda x: int(x, 16)).values.astype(np.uint8)
        ip_flags = np.unpackbits(ip_flags.reshape((-1, 1)), axis=1, bitorder="little")[
            :, :3
        ]

        # Unpack TCP flags (handle -1 for missing values)
        tcp_flags = (
            X["tcp.flags"]
            .apply(lambda x: int(x, 16) if x != -1 else 0)
            .values.astype(np.uint8)
        )
        tcp_flags = np.unpackbits(
            tcp_flags.reshape((-1, 1)), axis=1, bitorder="little"
        )[:, :9]

        # Combine flags into a single output array
        return np.hstack([ip_flags, tcp_flags])

    def port_to_categories(self, port):
        """Convert port number to category according to port_map."""
        for p_range, p_name in self.port_hierarchy_map_iot:
            if port in p_range:
                return p_name

        return ""
