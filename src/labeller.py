import pandas as pd
import re
from typing import List, Dict, Tuple


class Labeller:
    def __init__(self, normal_metadata: List[Dict[str, str]], malicious_metadata: List[Dict[str, str]]):
        self.normal_metadata = normal_metadata
        self.malicious_metadata = malicious_metadata

    @staticmethod
    def extract_device_info(filename: str) -> Tuple[str, str]:
        """Extract the IoT device type and its corresponding number from the filename."""
        match = re.match(r"([a-zA-Z\-]+)-([0-9]+)", filename)
        if match:
            return match.group(1), match.group(2)  # (device_name, device_number)
        return None, None

    @staticmethod
    def filter_traffic_by_device(df: pd.DataFrame, device_ip_address: str) -> pd.DataFrame:
        """Filter DataFrame for rows matching the given device IP address."""
        mask = (df["ip.src"].str.match(device_ip_address)) | (df["ip.dst"].str.match(device_ip_address))
        return df[mask]

    def label_normal_traffic_by_ip(self, df: pd.DataFrame, device_ip_address: str, device_info) -> pd.DataFrame:
        """Label packets based on IP address rules for normal traffic."""
        servers_ip = device_info.get("server_ip", [])
        for server_ip in servers_ip:
            server_ip = server_ip
            label = device_info["label"]

            mask = ((df["ip.src"] == device_ip_address) & (df["ip.dst"] == server_ip)) | ((df["ip.dst"] == device_ip_address) & (df["ip.src"] == server_ip))
            df.loc[mask, "label"] = label
        return df

    def label_malicious_traffic_by_ip(self, df: pd.DataFrame) -> pd.DataFrame:
        """Label packets based on IP address and port rules for malicious traffic."""
        for rule in self.malicious_metadata:
            src_ip = rule["source_ip"].replace("x.x", ".*")
            dst_ip = rule["destination_ip"].replace("x.x", ".*")
            label = rule["label"]

            src_port = rule.get("source_port")
            dst_port = rule.get("destination_port")
            protocol = rule.get("protocol")

            mask = df["ip.src"].str.match(src_ip) & df["ip.dst"].str.match(dst_ip)
            
            if src_port and dst_port:
                mask &= (df["tcp.srcport"] == src_port) & (df["tcp.dstport"] == dst_port)
            if protocol:
                mask &= (df["ip.proto"] == int(protocol))

            df.loc[mask & (df["label"] == "Unknown"), "label"] = label
        return df

    def label_data(self, filename: str, df: pd.DataFrame) -> pd.DataFrame:
        """Main function to label data using normal and malicious rules."""
        device_name, device_number_str = self.extract_device_info(filename)
        device_number = int(device_number_str) - 1
        device_info = self.normal_metadata.get(device_name, [])
        device_ip_address = device_info.get("device_ip", [])[device_number]

        # Filter traffic for the specific device
        df = self.filter_traffic_by_device(df, device_ip_address)

        # Initialize all labels to "Unknown"
        df['label'] = "Unknown"

        # Label normal and malicious traffic
        df = self.label_normal_traffic_by_ip(df, device_ip_address, device_info)
        df = self.label_malicious_traffic_by_ip(df)

        return df
