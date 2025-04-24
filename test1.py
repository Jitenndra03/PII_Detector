import spacy
import re

# Load English NLP model
nlp = spacy.load("en_core_web_sm")

# Sample text for testing
text = """
My name is Rajesh Kumar. My Aadhaar number is 1234-5678-9012.
Contact me at rajesh@example.com or +91-9876543210. I live in Delhi.
"""

# Run spaCy NLP pipeline
doc = nlp(text)

# Entities to extract using spaCy NER
named_entities = []
for ent in doc.ents:
    if ent.label_ in ["PERSON", "GPE", "ORG", "EMAIL", "PHONE", "LOC"]:
        named_entities.append((ent.text, ent.label_))

# Regex-based PII patterns
regex_patterns = {
    "Phone Number": r"\+91[-\s]?[6-9]\d{9}",
    "Email": r"[a-zA-Z0-9+._%\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "Aadhaar Number": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
}

# Extract PII with regex
regex_entities = []
for label, pattern in regex_patterns.items():
    matches = re.findall(pattern, text)
    for match in matches:
        regex_entities.append((match, label))

# Combine results
all_pii = named_entities + regex_entities

# Print results
print("Detected PII:")
for entity, label in all_pii:
    print(f"- {label}: {entity}")
