import os

EVENTS = [
    "normal",
    "coap-amplificator",
    "masscan",
    "merlin",
    "mirai-dos",
    "mirai-infection",
]
DATA_DIR = os.path.join(os.path.abspath("."), "data")
METADATA_DIR = os.path.join(os.path.abspath("."), "metadata")

__all__ = [
    "EVENTS",
    "DATA_DIR",
    "METADATA_DIR",
]
