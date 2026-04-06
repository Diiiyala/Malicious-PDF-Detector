import logging

def extract_text(reader):
    text = ""
    try:
        for page_num, page in enumerate(reader.pages):
            page_text = page.extract_text()
            if page_text:
                text += page_text
            else:
                logging.warning(f"No text on page {page_num}")
    except Exception as e:
        logging.error(f"Text extraction error: {e}")
    return text