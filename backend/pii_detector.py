from presidio_analyzer import AnalyzerEngine
import easyocr
from pathlib import Path
from pdf2image import convert_from_path
from PIL import Image
import cv2
import numpy as np
import tempfile

# Initialize OCR and PII Analyzer
reader = easyocr.Reader(['en'], gpu=False)
analyzer = AnalyzerEngine()

def extract_text_from_file(file_path):
    file_path = Path(file_path)
    
    # Handle PDF files
    if file_path.suffix.lower() == '.pdf':
        images = convert_from_path(str(file_path))
        texts = []
        for image in images:
            text = reader.readtext(np.array(image), detail=0, paragraph=True)
            texts.extend(text)
        return '\n'.join(texts)

    # Handle Image files (jpg, png, etc.)
    elif file_path.suffix.lower() in ['.jpg', '.jpeg', '.png']:
        image = cv2.imread(str(file_path))
        text = reader.readtext(image, detail=0, paragraph=True)
        return '\n'.join(text)
    
    else:
        raise ValueError("Unsupported file type!")

def detect_pii(text):
    results = analyzer.analyze(text=text, language='en')
    pii_list = [(res.entity_type, text[res.start:res.end]) for res in results]
    return pii_list

if __name__ == "__main__":
    # 🔽 CHANGE THIS TO YOUR FILE PATH
    file_path = "path/to/your/identity_document.pdf"  # or .jpg/.png

    print("\n📄 Extracting text...")
    text = extract_text_from_file(file_path)
    print(f"\n🔍 Extracted Text:\n{text}")

    print("\n🛡️ Detecting PII...")
    pii = detect_pii(text)
    print("\n🔐 Detected PII Entities:")
    for entity_type, value in pii:
        print(f"{entity_type}: {value}")
