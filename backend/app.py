from flask import Flask, request, jsonify, send_file
from flask_cors import CORS, cross_origin
import easyocr
import yara
import fitz  # PyMuPDF
import cv2
from PIL import Image, ImageFilter
import io
import numpy as np
import re
import os
from presidio_analyzer import AnalyzerEngine

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "allow_headers": "*", "supports_credentials": True}})

# Initialize EasyOCR Reader
reader = easyocr.Reader(['en', 'hi'])

# Define desired PII types to recognize
desired_recognizers = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "PASSPORT"]

# Compile YARA rules when the app starts
try:
    rules = yara.compile(filepath='scan_rules.yara')
except Exception as e:
    print(f"Error compiling YARA rules: {e}")
    rules = None

# Initialize Presidio Analyzer
analyzer = AnalyzerEngine()

def scan_text_with_yara(text):
    """Scan text with YARA rules for potential malicious content."""
    if rules is None:
        return []
        
    try:
        matches = rules.match(data=text)
        matched_rules = [match.rule for match in matches]
        return matched_rules
    except Exception as e:
        print(f"Error scanning with YARA: {e}")
        return []

# def detect_pii(text):
#     """Detect PII in the provided text using Presidio and custom regex patterns."""
#     # Detect PII with Presidio
#     results = analyzer.analyze(
#         text=text, 
#         language='en',
#         entities=desired_recognizers
#     )
    
#     pii_results = []

#     for result in results:
#         # Check if 'text' attribute is present
#         if hasattr(result, 'text'):
#             value = result.text
#         else:
#             # Fallback to result.start and result.end to extract the text substring
#             value = text[result.start:result.end]

#         pii_results.append({
#             'entity_type': result.entity_type,
#             'start': result.start,
#             'end': result.end,
#             'value': value
#         })

#     # Custom regex patterns
#     patterns = {
#         'AADHAAR_NUMBER': r'\b\d{4}\s\d{4}\s\d{4}\b',
#         'PAN_NUMBER': r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
#         'BLOOD_GROUP': r'\b(?:A|B|AB|O)[+-]\b',
#         'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
#         'CREDIT_CARD': r'\b(?:\d[ -]*?){13,16}\b'
#     }

#     for label, pattern in patterns.items():
#         for match in re.finditer(pattern, text):
#             if not any(r['entity_type'] == label for r in pii_results):
#                 pii_results.append({
#                     'entity_type': label,
#                     'start': match.start(),
#                     'end': match.end(),
#                     'value': match.group()
#                 })

#     return pii_results

def detect_pii(text):
    """Detect PII in the provided text using Presidio and custom regex patterns."""
    # Detect PII with Presidio
    results = analyzer.analyze(
        text=text, 
        language='en',
        entities=desired_recognizers
    )
    
    pii_results = []

    for result in results:
        # Extract the actual text
        value = text[result.start:result.end]
        
        # Only add if value is not empty
        if value.strip():
            pii_results.append({
                'entity_type': result.entity_type,
                'start': result.start,
                'end': result.end,
                'value': value
            })

    # Enhanced regex patterns
    patterns = {
        'AADHAAR_NUMBER': r'\b\d{4}\s\d{4}\s\d{4}\b',
        'PAN_NUMBER': r'\b[A-Z]{5}[0-9]{4}[A-Z]\b',
        'BLOOD_GROUP': r'\b(?:A|B|AB|O)[+-]\b',
        'PHONE_NUMBER': r'\b\d{10}\b',
        'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
#        'CREDIT_CARD': r'\b(?:\d[ -]*?){13,16}\b'
    }

    for label, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            value = match.group()
            # Check if this exact value hasn't been added already
            if not any(r['value'] == value for r in pii_results):
                pii_results.append({
                    'entity_type': label,
                    'start': match.start(),
                    'end': match.end(),
                    'value': value
                })

    return pii_results

def list_detected_pii(text, results):
    """List detected PII types and their values."""
    pii_list = {}
    for result in results:
        entity_text = result['value']
        pii_list[entity_text] = result['entity_type']  # Use actual text as the key
    return pii_list

def scan_pdf_for_images_and_qrcodes(pdf_doc):
    """Scan PDF for images, QR codes, and signatures."""
    images = []
    qrcodes = []
    signatures = []

    # Try to detect QR codes using OpenCV's QR code detector
    qr_detector = cv2.QRCodeDetector()

    for page_num in range(len(pdf_doc)):
        page = pdf_doc.load_page(page_num)
        image_list = page.get_images(full=True)

        for img in image_list:
            xref = img[0]
            base_image = pdf_doc.extract_image(xref)
            image_bytes = base_image["image"]
            
            # Save image to an in-memory buffer
            image = Image.open(io.BytesIO(image_bytes))
            images.append(image)
            
            # Convert PIL image to OpenCV format
            open_cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)

            # Detect QR codes using OpenCV
            try:
                retval, decoded_info, points, straight_qrcode = qr_detector.detectAndDecodeMulti(open_cv_image)
                if retval:
                    qrcodes.extend([info for info in decoded_info if info])
            except Exception as e:
                print(f"Error detecting QR code: {e}")

            # Heuristic to detect signatures
            if is_likely_signature(image):
                signatures.append(image)

    return images, qrcodes, signatures

def is_likely_signature(image):
    """
    Improved heuristic function to determine if the image is a signature.
    This approach analyzes the image for features commonly found in human signatures.
    """
    try:
        # Convert the image to OpenCV format
        open_cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        
        # Convert the image to grayscale
        gray_image = cv2.cvtColor(open_cv_image, cv2.COLOR_BGR2GRAY)

        # Apply binary threshold to get a black-and-white image
        _, binary_image = cv2.threshold(gray_image, 150, 255, cv2.THRESH_BINARY_INV)

        # Find contours in the binary image
        contours, _ = cv2.findContours(binary_image, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

        # Initialize variables for heuristics
        total_contour_area = 0
        total_contour_perimeter = 0
        contour_count = 0
        likely_signature = False

        # Loop through the contours to compute heuristic metrics
        for contour in contours:
            # Compute contour area and perimeter
            contour_area = cv2.contourArea(contour)
            contour_perimeter = cv2.arcLength(contour, True)

            # Filter out very small or very large contours (noise or background)
            if contour_area > 50 and contour_area < 2000:
                total_contour_area += contour_area
                total_contour_perimeter += contour_perimeter
                contour_count += 1

        if contour_count > 0:
            # Compute average contour area and perimeter
            avg_area = total_contour_area / contour_count
            avg_perimeter = total_contour_perimeter / contour_count

            # Heuristic rule: Signatures often have many small, continuous strokes
            # Check if the area/perimeter ratio and contour count fall within a signature-like range
            if avg_area > 100 and avg_perimeter > 50 and contour_count > 5:
                likely_signature = True

        return likely_signature
    except Exception as e:
        print(f"Error analyzing for signature: {e}")
        return False

def extract_pdf_pages_as_images(pdf_path):
    """Extract each page of a PDF as a PIL Image."""
    try:
        pdf_doc = fitz.open(pdf_path)
        images = []

        for page_num in range(len(pdf_doc)):
            page = pdf_doc.load_page(page_num)
            pix = page.get_pixmap()
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            images.append(img)

        return images
    except Exception as e:
        print(f"Error extracting PDF pages as images: {e}")
        return []

# def detect_pii_with_easyocr(image, edited_pii_data):
#     """Detect PII in images using EasyOCR and match with edited PII data."""
#     try:
#         # Convert PIL image to NumPy array
#         image_np = np.array(image)

#         result = reader.readtext(image_np)

#         pii_coordinates = []
#         for (bbox, text, _) in result:
#             for pii_key in edited_pii_data.keys():
#                 if pii_key.lower() in text.lower():
#                     # bbox from EasyOCR is a list of four points: [[x1,y1],[x2,y1],[x2,y2],[x1,y2]]
#                     pii_coordinates.append((bbox, text, edited_pii_data[pii_key]))
#         return pii_coordinates
#     except Exception as e:
#         print(f"Error detecting PII with EasyOCR: {e}")
#         return []

def detect_pii_with_easyocr(image, edited_pii_data):
    """Improved function to detect PII in images using EasyOCR."""
    try:
        # Convert to numpy array for OCR
        image_np = np.array(image)
        
        # Use higher resolution for better accuracy
        h, w = image_np.shape[:2]
        if max(h, w) < 1000:
            scale = 1000 / max(h, w)
            image_np = cv2.resize(image_np, None, fx=scale, fy=scale)
        
        # Run OCR with better confidence
        result = reader.readtext(image_np, paragraph=False, min_size=10)
        
        pii_coordinates = []
        for (bbox, text, prob) in result:
            # Only consider text with good confidence
            if prob > 0.5:  # Adjust threshold as needed
                for pii_key in edited_pii_data.keys():
                    # Check if PII exactly matches or is contained
                    if pii_key == text or pii_key in text:
                        # Scale coordinates back if we resized
                        if max(h, w) < 1000:
                            scaled_bbox = [[point[0]/scale, point[1]/scale] for point in bbox]
                        else:
                            scaled_bbox = bbox
                            
                        pii_coordinates.append((scaled_bbox, text, edited_pii_data[pii_key]))
                        break
        
        return pii_coordinates
    except Exception as e:
        print(f"Error detecting PII with EasyOCR: {e}")
        return []

def redact_pdf_with_coordinates(pdf_path, pii_coordinates, image_masking_options):
    """Redact a PDF using coordinates from PII detection."""
    try:
        pdf_doc = fitz.open(pdf_path)
        white_color = (1.0, 1.0, 1.0)
        black_color = (0.0, 0.0, 0.0)
        fontsize = 12

        for page_num in range(len(pdf_doc)):
            page = pdf_doc.load_page(page_num)
            
            # Redact the text based on coordinates
            for bbox, original_text, new_value in pii_coordinates:
                # Convert EasyOCR bbox format to PyMuPDF rect
                # EasyOCR returns [[x1,y1],[x2,y1],[x2,y2],[x1,y2]]
                x0 = min(point[0] for point in bbox)
                y0 = min(point[1] for point in bbox)
                x1 = max(point[0] for point in bbox)
                y1 = max(point[1] for point in bbox)
                rect = fitz.Rect(x0, y0, x1, y1)

                # Create redaction annotation and fill with white color
                page.add_redact_annot(rect, fill=white_color)
                page.apply_redactions()

                # Now insert the new value on top of the redaction
                if new_value:
                    text_position = (rect.x0, rect.y0 + fontsize)
                    page.insert_text(text_position, new_value, fontsize=fontsize, color=black_color)

        # Ensure the masked directory exists
        if not os.path.exists('masked'):
            os.makedirs('masked')
            
        masked_file_name = 'masked_' + os.path.basename(pdf_path)
        masked_file_path = os.path.join('masked', masked_file_name)
        pdf_doc.save(masked_file_path)
        pdf_doc.close()
        return masked_file_path
    except Exception as e:
        print(f"Error redacting PDF: {e}")
        return None

def is_image_only_pdf(pdf_doc):
    """
    Check if a PDF is an image-based PDF (scanned PDF).
    If all pages contain only images and no text, it's likely an image-based PDF.
    """
    try:
        image_only = True

        for page_num in range(len(pdf_doc)):
            page = pdf_doc.load_page(page_num)
            text = page.get_text()  # Extract text from the page
            
            if text.strip():
                # If any page has text, it's not an image-only PDF
                image_only = False
                break

        return image_only
    except Exception as e:
        print(f"Error checking if PDF is image-only: {e}")
        return False

def apply_masking(image, option):
    """Apply masking options (blur or remove) to the image."""
    try:
        if option == "blur":
            return image.filter(ImageFilter.GaussianBlur(10))
        elif option == "remove":
            return None
        return image
    except Exception as e:
        print(f"Error applying mask to image: {e}")
        return image

def extract_text_from_pdf(file_path):
    """Extract text from PDF using EasyOCR."""
    try:
        pdf_text = ""
        pdf_doc = fitz.open(file_path)

        for page_num in range(len(pdf_doc)):
            page = pdf_doc.load_page(page_num)
            # Extract image for OCR
            pix = page.get_pixmap()
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            text = reader.readtext(np.array(img))
            page_text = " ".join([item[1] for item in text])
            pdf_text += page_text

        return pdf_text
    except Exception as e:
        print(f"Error extracting text from PDF: {e}")
        return ""

@app.route('/scan_and_upload', methods=['POST'])
@cross_origin()
def scan_and_upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"})

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"})

    try:
        if file and file.filename.endswith('.pdf'):
            # Ensure upload directory exists
            if not os.path.exists('uploads'):
                os.makedirs('uploads')
                
            file_path = os.path.join('uploads', file.filename)
            file.save(file_path)

            # Load PDF to determine if it is image-only or text-based
            pdf_doc = fitz.open(file_path)
            is_image_only = is_image_only_pdf(pdf_doc)
            
            text = ""
            if is_image_only:
                # Extract text from images in the PDF using EasyOCR
                text = extract_text_from_pdf(file_path)
            else:
                # Extract text from the PDF using fitz for text-based PDFs
                for page_num in range(len(pdf_doc)):
                    page = pdf_doc.load_page(page_num)
                    text += page.get_text()
                
            # Scan PDF for images, QR codes, and signatures
            images, qrcodes, signatures = scan_pdf_for_images_and_qrcodes(pdf_doc)

            # Step 2: Scan the text with YARA
            matched_rules = scan_text_with_yara(text)
            if matched_rules:
                return jsonify({
                    'malicious': True, 
                    'matched_rules': matched_rules
                })

            # Step 3: If no malicious content, proceed with PII detection
            pii_results = detect_pii(text)
            pii_list = list_detected_pii(text, pii_results)

            return jsonify({
                "malicious": False, 
                "pii_list": pii_list, 
                "images_detected": len(images), 
                "qrcodes_detected": len(qrcodes),
                "signatures_detected": len(signatures),
                "file_path": file_path,
                "is_image_only": is_image_only
            })
        else:
            return jsonify({"error": "Unsupported file format"})
    except Exception as e:
        return jsonify({"error": f"Error processing file: {str(e)}"})

# @app.route('/mask', methods=['POST'])
# def mask_file():
#     try:
#         data = request.json
#         file_path = data['file_path']
#         edited_pii_data = data['edited_pii_data']
#         image_masking_options = data.get('image_masking_options', {})
#         is_image_only = data.get('is_image_only', False)
        
#         # Ensure the 'masked' directory exists
#         masked_dir = 'masked'
#         if not os.path.exists(masked_dir):
#             os.makedirs(masked_dir)

#         if not os.path.isfile(file_path):
#             return jsonify({"error": "File not found"})
        
#         if is_image_only:
#             # Handle image-only PDFs
#             # Extract images from PDF pages
#             images = extract_pdf_pages_as_images(file_path)

#             # Detect PII using EasyOCR
#             pii_coordinates = []
#             for img in images:
#                 detected_pii = detect_pii_with_easyocr(img, edited_pii_data)
#                 pii_coordinates.extend(detected_pii)
                
#             # Apply redaction/masking based on the coordinates detected by EasyOCR
#             masked_file_path = redact_pdf_with_coordinates(file_path, pii_coordinates, image_masking_options)
            
#             if not masked_file_path:
#                 return jsonify({"error": "Failed to create masked file"}), 500
#         else:
#             # Handle text-based PDFs
#             pdf_doc = fitz.open(file_path)

#             # Define colors in normalized range [0, 1]
#             white_color = (1.0, 1.0, 1.0)
#             black_color = (0.0, 0.0, 0.0)
#             fontsize = 12

#             for page_num in range(len(pdf_doc)):
#                 page = pdf_doc.load_page(page_num)

#                 for entity_text, new_value in edited_pii_data.items():
#                     # Search for the text
#                     areas = page.search_for(entity_text)
#                     for area in areas:
#                         # Directly redact the original text (erases it permanently)
#                         page.add_redact_annot(area, fill=white_color)

#                         # Apply the redaction to remove the text
#                         page.apply_redactions()

#                         # Insert new text over the redacted area if a replacement was provided
#                         if new_value:
#                             text_rect = fitz.Rect(area.x0, area.y0, area.x1, area.y1)
#                             page.insert_text(text_rect.tl, new_value, fontsize=fontsize, color=black_color)

#                 # Process images based on masking options
#                 image_list = page.get_images(full=True)
#                 for img in image_list:
#                     xref = img[0]
#                     mask_option = image_masking_options.get("images", "none")

#                     if mask_option == "remove":
#                         # Remove the image entirely from the page
#                         rects = page.get_image_rects(xref)
#                         if rects:
#                             for rect in rects:
#                                 page.add_redact_annot(rect, fill=white_color)
#                             page.apply_redactions()
#                     elif mask_option == "blur":
#                         try:
#                             base_image = pdf_doc.extract_image(xref)
#                             image_bytes = base_image["image"]
#                             image = Image.open(io.BytesIO(image_bytes))
#                             masked_image = apply_masking(image, mask_option)

#                             if masked_image:
#                                 # Convert masked image back to bytes
#                                 img_byte_arr = io.BytesIO()
#                                 masked_image.save(img_byte_arr, format='PNG')
#                                 img_byte_arr = img_byte_arr.getvalue()

#                                 # Replace the original image in the PDF with the masked image
#                                 rect = page.get_image_rects(xref)[0]  # First rectangle
#                                 page.delete_image(xref)  # Remove the original image
#                                 page.insert_image(rect, stream=img_byte_arr)  # Insert the blurred image
#                         except Exception as e:
#                             print(f"Error processing image {xref}: {e}")

#             masked_file_name = 'masked_' + os.path.basename(file_path)
#             masked_file_path = os.path.join('masked', masked_file_name)
#             pdf_doc.save(masked_file_path)
#             pdf_doc.close()

#         response = {
#             "file_path": masked_file_path
#         }
#         return jsonify(response), 200
#     except Exception as e:
#         return jsonify({"error": f"Error masking file: {str(e)}"}), 500
@app.route('/mask', methods=['POST'])
def mask_file():
    try:
        data = request.json
        file_path = data['file_path']
        edited_pii_data = data['edited_pii_data']
        image_masking_options = data.get('image_masking_options', {})
        is_image_only = data.get('is_image_only', False)
        
        # Ensure the 'masked' directory exists
        masked_dir = 'masked'
        if not os.path.exists(masked_dir):
            os.makedirs(masked_dir)

        if not os.path.isfile(file_path):
            return jsonify({"error": "File not found"})
        
        if is_image_only:
            # Handle image-only PDFs
            images = extract_pdf_pages_as_images(file_path)

            pii_coordinates = []
            for img in images:
                detected_pii = detect_pii_with_easyocr(img, edited_pii_data)
                pii_coordinates.extend(detected_pii)
                
            masked_file_path = redact_pdf_with_coordinates(file_path, pii_coordinates, image_masking_options)
            
            if not masked_file_path:
                return jsonify({"error": "Failed to create masked file"}), 500
        else:
            # Handle text-based PDFs
            pdf_doc = fitz.open(file_path)

            white_color = (1.0, 1.0, 1.0)
            black_color = (0.0, 0.0, 0.0)
            fontsize = 12

            for page_num in range(len(pdf_doc)):
                page = pdf_doc.load_page(page_num)

                # ====== NEW: Remove links/URIs containing PII ======
                annots = page.annots()
                if annots:
                    for annot in annots:
                        if annot.type[0] == 1:  # URI link
                            uri = annot.uri
                            for entity_text in edited_pii_data.keys():
                                if entity_text.lower() in uri.lower():
                                    page.delete_annot(annot)

                # ====== NEW: Redact hidden or block text ======
                blocks = page.get_text("blocks")
                for block in blocks:
                    block_text = block[4]
                    for entity_text in edited_pii_data.keys():
                        if entity_text.lower() in block_text.lower():
                            block_rect = fitz.Rect(block[:4])
                            page.add_redact_annot(block_rect, fill=white_color)

                # ====== Existing: Redact normal visible text ======
                for entity_text, new_value in edited_pii_data.items():
                    areas = page.search_for(entity_text)
                    for area in areas:
                        page.add_redact_annot(area, fill=white_color)

                # ====== Apply all redactions ======
                page.apply_redactions()

                # ====== Insert new text after redaction ======
                for entity_text, new_value in edited_pii_data.items():
                    if new_value:
                        areas = page.search_for(entity_text)
                        for area in areas:
                            text_rect = fitz.Rect(area.x0, area.y0, area.x1, area.y1)
                            page.insert_text(text_rect.tl, new_value, fontsize=fontsize, color=black_color)

                # ====== (Optional) Handle image masking ======
                image_list = page.get_images(full=True)
                for img in image_list:
                    xref = img[0]
                    mask_option = image_masking_options.get("images", "none")

                    if mask_option == "remove":
                        rects = page.get_image_rects(xref)
                        if rects:
                            for rect in rects:
                                page.add_redact_annot(rect, fill=white_color)
                            page.apply_redactions()
                    elif mask_option == "blur":
                        try:
                            base_image = pdf_doc.extract_image(xref)
                            image_bytes = base_image["image"]
                            image = Image.open(io.BytesIO(image_bytes))
                            masked_image = apply_masking(image, mask_option)

                            if masked_image:
                                img_byte_arr = io.BytesIO()
                                masked_image.save(img_byte_arr, format='PNG')
                                img_byte_arr = img_byte_arr.getvalue()

                                rect = page.get_image_rects(xref)[0]
                                page.delete_image(xref)
                                page.insert_image(rect, stream=img_byte_arr)
                        except Exception as e:
                            print(f"Error processing image {xref}: {e}")

            # ====== Save masked file ======
            masked_file_name = 'masked_' + os.path.basename(file_path)
            masked_file_path = os.path.join('masked', masked_file_name)
            pdf_doc.save(masked_file_path)
            pdf_doc.close()

        response = {
            "file_path": masked_file_path
        }
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": f"Error masking file: {str(e)}"}), 500


@app.route('/download/<path:filename>', methods=['GET'])
@cross_origin()
def download_file(filename):
    try:
        file_path = filename
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": f"Error downloading file: {str(e)}"}), 500

if __name__ == '__main__':
    # Ensure required directories exist
    for directory in ['uploads', 'masked']:
        if not os.path.exists(directory):
            os.makedirs(directory)
            
    app.run(debug=True)


