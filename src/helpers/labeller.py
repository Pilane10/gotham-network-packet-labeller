import pandas as pd
import re
from typing import List, Dict, Tuple


class Labeller:
    def __init__(
        self,
        normal_metadata: List[Dict[str, str]],
        malicious_metadata: List[Dict[str, str]],
    ):
        """
        Initializes the Labeller with normal and malicious metadata.

        Args:
            normal_metadata: A dictionary with device names as keys and their metadata as values.
            malicious_metadata: A list of dictionaries containing malicious traffic rules.
        """
        self.normal_metadata = normal_metadata
        self.malicious_metadata = malicious_metadata

    @staticmethod
    def extract_device_info(filename: str) -> Tuple[str, str]:
        """
        Extract the IoT device type and its corresponding number from the filename.

        Args:
            filename: The input filename to parse.

        Returns:
            A tuple containing the device name and device number.
        """
        match = re.match(r"([a-zA-Z\-]+)-([0-9]+)", filename)
        if match:
            return (
                match.group(1),
                int(match.group(2)) - 1,
            )  # (device_name, device_number)

        return None, None

    @staticmethod
    def filter_traffic_by_device(
        df: pd.DataFrame, device_ip_address: str
    ) -> pd.DataFrame:
        """
        Filter DataFrame for rows matching the given device IP address.

        Args:
            df: Input DataFrame containing traffic data.
            device_ip_address: IP address of the IoT device.

        Returns:
            A filtered DataFrame containing only relevant traffic.
        """
        if not device_ip_address:
            raise ValueError("Device IP address is required for filtering.")

        mask = (df["ip.src"] == device_ip_address) | (df["ip.dst"] == device_ip_address)

        return df[mask]

    @staticmethod
    def label_normal_traffic_by_ip(
        df: pd.DataFrame, device_ip_address: str, device_info
    ) -> pd.DataFrame:
        """
        Label packets as normal traffic based on server IPs and device IP rules.

        Args:
            df: Input DataFrame to label.
            device_ip_address: The IP address of the IoT device.
            device_info: Metadata of the IoT device, including server IPs.

        Returns:
            A DataFrame with labeled normal traffic.
        """
        servers_ip = device_info.get("server_ip", [])
        label = device_info.get("label", "Normal")

        for server_ip in servers_ip:
            mask = (
                (df["ip.src"] == device_ip_address) & (df["ip.dst"] == server_ip)
            ) | ((df["ip.dst"] == device_ip_address) & (df["ip.src"] == server_ip))
            df.loc[mask, "label"] = label

        return df

    def label_malicious_traffic_by_ip(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Label packets as malicious traffic based on rules from malicious metadata.

        Args:
            df: Input DataFrame to label.

        Returns:
            A DataFrame with labeled malicious traffic.
        """
        for rule in self.malicious_metadata:
            src_ip = rule.get("source_ip", "").replace("x.x", ".*")
            dst_ip = rule.get("destination_ip", "").replace("x.x", ".*")
            label = rule.get("label", "Malicious")

            mask = df["ip.src"].str.match(src_ip) & df["ip.dst"].str.match(dst_ip)

            if "source_port" in rule and "destination_port" in rule:
                mask &= (df["tcp.srcport"] == rule["source_port"]) & (
                    df["tcp.dstport"] == rule["destination_port"]
                )
            if "protocol" in rule:
                mask &= df["ip.proto"] == int(rule["protocol"])

            df.loc[mask & (df["label"] == "Unknown"), "label"] = label

        return df

    def label_data(self, filename: str, df: pd.DataFrame) -> pd.DataFrame:
        """
        Main function to label the data for a specific IoT device.

        Args:
            filename: The filename containing device identification info.
            df: Input DataFrame containing network traffic.

        Returns:
            A DataFrame with labeled network traffic.
        """
        # Extract device info
        device_name, device_index = self.extract_device_info(filename)
        if device_name is None or device_index is None:
            raise ValueError(
                f"Filename '{filename}' is invalid or does not match the expected format."
            )

        # Retrieve device metadata
        device_info = self.normal_metadata.get(device_name, [])
        if not device_info:
            raise ValueError(f"No metadata found for device '{device_name}'.")

        device_ips = device_info.get("device_ip", [])
        if len(device_ips) <= device_index:
            raise IndexError(
                f"Device index '{device_index}' is out of range for device '{device_name}'."
            )

        device_ip_address = device_ips[device_index]

        # Filter traffic for this device
        df = self.filter_traffic_by_device(df, device_ip_address)

        # Initialize all labels to "Unknown"
        df["label"] = "Unknown"

        # Label normal and malicious traffic
        df = self.label_normal_traffic_by_ip(df, device_ip_address, device_info)
        df = self.label_malicious_traffic_by_ip(df)

        return df
