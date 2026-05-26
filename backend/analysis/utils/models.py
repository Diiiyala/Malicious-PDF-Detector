from dataclasses import dataclass, field
from typing import List, Set, Dict

@dataclass
class Threat:
    id: str
    category: str
    severity: int
    description: str
    location: str

@dataclass
class ExtractedContent:
    filename: str = ""
    raw_binary: bytes = b""
    extracted_text: str = ""
    metadata_dict: Dict = field(default_factory=dict)
    extracted_urls: Set[str] = field(default_factory=set)
    embedded_scripts: List[Dict] = field(default_factory=list)
    pdf_version: str = ""
    has_encryption: bool = False
    structure_paths: Set[str] = field(default_factory=set)
    visual_anomalies: List[Dict] = field(default_factory=list)
    image_only_pages: List[int] = field(default_factory=list)
    has_malformed_pages_tree: bool = False