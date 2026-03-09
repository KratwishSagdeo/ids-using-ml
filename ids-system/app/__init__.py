# IDS System Package
__version__ = "1.0.0"
__author__ = "IDS Development Team"

try:
    from .db import IDSDatabase
except ImportError:
    IDSDatabase = None

try:
    from .feature_extractor import FeatureExtractor
except ImportError:
    FeatureExtractor = None

try:
    from .pcap_analyzer import PCAPAnalyzer
except ImportError:
    PCAPAnalyzer = None

try:
    from .realtime_ids import RealtimeIDS
except ImportError:
    RealtimeIDS = None

try:
    from .pcap_feature_bridge import PCAPFeatureBridge
except ImportError:
    PCAPFeatureBridge = None

__all__ = [
    "IDSDatabase",
    "FeatureExtractor",
    "PCAPAnalyzer",
    "RealtimeIDS",
    "PCAPFeatureBridge"
]
