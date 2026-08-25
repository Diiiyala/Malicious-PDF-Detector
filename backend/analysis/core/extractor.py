import logging, re
from analysis.utils.models import ExtractedContent
from analysis.utils.text_extractor import extract_text_and_visuals
from analysis.utils.pdf_strings import extract_pdf_literal_string

logger = logging.getLogger(__name__)

def extract_all_data(reader, raw_file_content, filename) -> ExtractedContent:
    content = ExtractedContent(filename=filename, raw_binary=raw_file_content)
    
    # 1. Metadata
    if reader and reader.metadata:
        content.metadata_dict = reader.metadata
        
    # 2. Text
    if reader:
        try:
            text_data = extract_text_and_visuals(reader) 
            content.extracted_text = text_data["text"]
            content.visual_anomalies = text_data["anomalies"]
            content.image_only_pages = text_data["image_only_pages"]
            content.has_malformed_pages_tree = text_data["malformed_tree"]
            
        except Exception as e:
            logger.warning("Text extraction failed: %s", e)
            content.extracted_text = ""
        
    # 3. URI
    for match in re.finditer(rb'/URI\s*\(', raw_file_content):
        uri = extract_pdf_literal_string(raw_file_content, match.end())
        if uri:
            content.extracted_urls.add(uri)
    
    # 4. Encryption Status
    if reader and reader.is_encrypted:
        content.has_encryption = True

    return content