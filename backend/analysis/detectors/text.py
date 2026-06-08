from analysis.utils.models import ExtractedContent, Threat

def detect_text_anomalies(content: ExtractedContent) -> list[Threat]:
    threats = []
    
    if content.has_malformed_pages_tree:
        threats.append(Threat(
            id="TXT-TREE-MALFORMED",
            category="Text Extraction",
            severity=9,
            description="Text extraction skipped (Malformed or missing Pages tree)",
            location="Document Tree"
        ))

    for anomaly in content.visual_anomalies:
        a_type = anomaly.get("type")
        
        if a_type == "tiny_font":
            threats.append(Threat(
                id="TXT-HIDDEN-TINY",
                category="Text Extraction",
                severity=10,
                description=f"Hidden text detected (Tiny Font: {anomaly.get('size')}pt): '{anomaly.get('text')}'",
                location="Text Elements"
            ))
            
        elif a_type == "off_canvas":
            threats.append(Threat(
                id="TXT-HIDDEN-CANVAS",
                category="Text Extraction",
                severity=8,
                description=f"Hidden text detected (Off-Canvas at {anomaly.get('x')},{anomaly.get('y')}): '{anomaly.get('text')}'",
                location="Text Elements"
            ))
            
        elif a_type == "encoding":
            threats.append(Threat(
                id="TXT-FONT-ENCODING",
                category="Text Extraction",
                severity=3,
                description=f"Non-standard font encoding detected ({anomaly.get('details')})",
                location="Text Elements"
            ))
            
        elif a_type == "transformation":
            threats.append(Threat(
                id="TXT-TRANSFORM",
                category="Text Extraction",
                severity=3,
                description=f"Text transformation detected ({anomaly.get('details')})",
                location="Text Elements"
            ))
            
        elif a_type == "flipped":
            threats.append(Threat(
                id="TXT-FLIPPED",
                category="Text Extraction",
                severity=4,
                description=f"Flipped/mirrored text detected ({anomaly.get('details')})",
                location="Text Elements"
            ))

    return threats