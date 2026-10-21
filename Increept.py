import streamlit as st
from PIL import Image
import base64
import io
import re
import hashlib

MAGIC_HEADER = "STG1|"
TERMINATOR = "|END_STG"
MAX_IMAGE_WIDTH = 800

st.set_page_config(page_title="iNcreept", page_icon="👾", layout="wide")


st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

    html, body, [class*="css"], .stMarkdown, .stText, input, textarea, button {
        font-family: 'Share Tech Mono', 'Courier New', monospace !important;
        color: #00ff41 !important;
    }

    .stApp {
        background-color: #0a0a0a;
        min-height: 100vh;
        width: 100vw;
        border: 2px solid #00ff41;
        box-sizing: border-box;
    }

    button[data-baseweb="tab"] {
        background-color: transparent !important;
        color: #777777 !important;
        border: none !important;
        border-bottom: 2px solid #262626 !important;
        border-radius: 0px !important;
        margin-right: 16px !important;
        padding: 8px 12px !important;
        font-weight: bold !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #00ff41 !important;
        border-bottom: 2px solid #00ff41 !important;
        font-weight: bold !important;
    }

    header[data-testid="stHeader"] {
        background: transparent !important;
    }

    .block-container {
        max-width: 92% !important;
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
    }

    div[data-testid="stVerticalBlock"] > div {
        background-color: transparent;
        border: none;
        padding: 4px 0px;
        box-shadow: none;
    }

    .stTextInput input, .stTextArea textarea {
        background-color: #121212 !important;
        color: #00ff41 !important;
        border: 1px solid #2e2e2e !important;
        border-radius: 2px !important;
    }
    .stTextInput input:focus, .stTextArea textarea:focus {
        border-color: #00ff41 !important;
        box-shadow: none !important;
    }

    .stButton > button, .stDownloadButton > button {
        background-color: #121212 !important;
        color: #00ff41 !important;
        border: 1px solid #00ff41 !important;
        border-radius: 2px !important;
        padding: 0.6rem 1.2rem !important;
        font-weight: bold !important;
        text-transform: uppercase !important;
        letter-spacing: 2px !important;
        transition: all 0.15s ease !important;
        width: 100%;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        background-color: #00ff41 !important;
        color: #0a0a0a !important;
    }

    button[data-baseweb="tab"] {
        background-color: transparent !important;
        color: #777777 !important;
        border: none !important;
        border-bottom: 2px solid #262626 !important;
        border-radius: 0px !important;
        margin-right: 16px !important;
        padding: 8px 12px !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #00ff41 !important;
        border-bottom: 2px solid #00ff41 !important;
        font-weight: bold !important;
    }

    [data-testid="stFileUploader"] {
        background-color: #121212 !important;
        border: 1px dashed #3a3a3a !important;
        padding: 12px;
        border-radius: 2px;
    }

    .psx-footer {
        margin-top: 40px;
        padding: 12px;
        background-color: #111111;
        border: 1px solid #2a2a2a;
        text-align: center;
        color: #888888 !important;
        font-size: 0.85rem;
        letter-spacing: 1px;
    }
</style>
""", unsafe_allow_html=True)

#Helper Functions

def get_key_signature(password):
    """Generates an 8-char verification tag from the entire password so wrong keys are caught 100% of the time."""
    if not password:
        return "NOKEY000"
    return hashlib.sha256(("PSX_AUTH_" + password).encode('utf-8')).hexdigest()[:8]

def xor_cipher(text, password):
    
    if not password:
        return text
    key_bytes = hashlib.sha256(password.encode('utf-8')).digest()
    return "".join(chr(ord(char) ^ key_bytes[i % len(key_bytes)]) for i, char in enumerate(text))

def text_to_bits(text):
    bits = []
    for char in text:
        bits.extend([int(b) for b in format(ord(char), '08b')])
    return bits

def embed_lsb(img, bits):
    pixels = list(img.getdata())
    max_bits = len(pixels) * 3
    if len(bits) > max_bits:
        return None
    
    new_pixels = []
    bit_idx = 0
    for p in pixels:
        r, g, b, a = p
        if bit_idx < len(bits):
            r = (r & 0xFE) | bits[bit_idx]
            bit_idx += 1
        if bit_idx < len(bits):
            g = (g & 0xFE) | bits[bit_idx]
            bit_idx += 1
        if bit_idx < len(bits):
            b = (b & 0xFE) | bits[bit_idx]
            bit_idx += 1
        new_pixels.append((r, g, b, a))
        
    img.putdata(new_pixels)
    return img

def extract_lsb(img):
    pixels = list(img.getdata())
    extracted = ""
    byte = 0
    bit_count = 0
    
    for p in pixels:
        r, g, b = p[:3]
        for channel in (r, g, b):
            byte = (byte << 1) | (channel & 1)
            bit_count += 1
            if bit_count == 8:
                extracted += chr(byte)
                if extracted.endswith(TERMINATOR):
                    return extracted
                byte = 0
                bit_count = 0
    return None

def decode_payload(safe_payload, password):
    try:
        start_idx = safe_payload.find(MAGIC_HEADER)
        end_idx = safe_payload.find(TERMINATOR)
        if start_idx == -1 or end_idx == -1:
            return "INVALID_PAYLOAD"
        
        b64_content = safe_payload[start_idx + len(MAGIC_HEADER):end_idx]
        raw_decoded = base64.b64decode(b64_content).decode('utf-8')
        
        if ":" not in raw_decoded:
            return "INVALID_PAYLOAD"
            
        stored_sig, encrypted_text = raw_decoded.split(":", 1)
        expected_sig = get_key_signature(password)
        
        if stored_sig != expected_sig:
            return "WRONG_KEY"
            
        return xor_cipher(encrypted_text, password)
    except Exception:
        return "WRONG_KEY"

# ui Heading
st.markdown("""
<div style="padding-bottom: 12px; margin-bottom: 20px; border-bottom: 1px solid #262626;">
    <h1 style="margin: 0; color: #00ff41; font-weight: bold; letter-spacing: 2px;">👾 iNcreept</h1>
    <div style="color: #777777; font-size: 0.85rem;font-weight:bold">ANTI-COMPRESSION STEGANOGRAPHY SUITE</div>
</div>
""", unsafe_allow_html=True)

tab1, tab2 = st.tabs([" 1. HIDE & PACKAGE", " 2. EXTRACT MESSAGE"])

#TAB-1:ENCODE
with tab1:
    uploaded_cover = st.file_uploader("1 // UPLOAD COVER IMAGE", type=["png", "jpg", "jpeg", "webp"])
    secret_text = st.text_area("2 // SECRET MESSAGE PAYLOAD", placeholder="Enter confidential message...")
    passkey_enc = st.text_input("3 // ENCRYPTION PASSKEY", type="password", help="Full key required on receiver end.")
    
    export_format = st.radio(
        "4 // SELECT OUTPUT EXTENSION",
        ["png", "pdf", "doc", "jpg"],
        horizontal=True,
        format_func=lambda x: {
            "png": ".PNG (Lossless)",
            "pdf": ".PDF (WhatsApp)",
            "doc": ".DOC (Document)",
            "jpg": ".JPG (Legacy)"
        }[x]
    )

    if st.button(" ENCRYPT & BUILD FILE"):
        if not uploaded_cover:
            st.error("[ERROR] Please upload a cover image first.")
        elif not secret_text:
            st.error("[ERROR] Please enter a secret message.")
        else:
            with st.spinner("Processing..."):
                img = Image.open(uploaded_cover).convert("RGBA")
                
                if img.width > MAX_IMAGE_WIDTH:
                    ratio = MAX_IMAGE_WIDTH / img.width
                    img = img.resize((MAX_IMAGE_WIDTH, int(img.height * ratio)), Image.Resampling.LANCZOS)
                
                key_sig = get_key_signature(passkey_enc)
                encrypted_msg = xor_cipher(secret_text, passkey_enc)
                combined_inner = f"{key_sig}:{encrypted_msg}"
                
                b64_msg = base64.b64encode(combined_inner.encode('utf-8')).decode('ascii')
                safe_payload = f"{MAGIC_HEADER}{b64_msg}{TERMINATOR}"
                bits = text_to_bits(safe_payload)
                
                stego_img = embed_lsb(img, bits)
                
                if stego_img is None:
                    st.error("[ERROR] Payload exceeds image capacity.")
                else:
                    out_buffer = io.BytesIO()
                    filename = f"increept_file.{export_format}"
                    mime = "application/octet-stream"

                    if export_format == "png":
                        stego_img.save(out_buffer, format="PNG", optimize=True)
                        mime = "image/png"
                    elif export_format == "jpg":
                        stego_img.convert("RGB").save(out_buffer, format="JPEG", quality=95, optimize=True)
                        out_buffer.write(f"\n<!--STEGO_BACKUP:{safe_payload}-->".encode('utf-8'))
                        mime = "image/jpeg"
                    elif export_format == "doc":
                        img_buf = io.BytesIO()
                        stego_img.save(img_buf, format="PNG", optimize=True)
                        b64_img = base64.b64encode(img_buf.getvalue()).decode('ascii')
                        png_data_url = f"data:image/png;base64,{b64_img}"
                        doc_content = f"""<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word'>
<body>
  <p>Attached Document Image:</p>
  <img src="{png_data_url}" style="max-width:100%;" />
  <!--STEGO_DATA_START:{png_data_url}:STEGO_DATA_END-->
</body></html>"""
                        out_buffer.write(doc_content.encode('utf-8'))
                        mime = "application/msword"
                    elif export_format == "pdf":
                        stego_img.convert("RGB").save(out_buffer, format="PDF", resolution=100.0)
                        out_buffer.write(f"\n%STEGO_BACKUP:{safe_payload}".encode('utf-8'))
                        mime = "application/pdf"

                    st.success("[OK] File ready for download.")
                    st.download_button(
                        label=f"□ DOWNLOAD {filename.upper()}",
                        data=out_buffer.getvalue(),
                        file_name=filename,
                        mime=mime
                    )

#TAB-2:DECODE
with tab2:
    uploaded_file = st.file_uploader("1 // UPLOAD RECEIVED FILE", type=["png", "jpg", "jpeg", "doc", "pdf"])
    passkey_dec = st.text_input("2 // DECRYPTION KEY", type="password", key="dec_pass")

    if st.button("× DECRYPT MESSAGE"):
        if not uploaded_file:
            st.error("[ERROR] Please upload a file to decode.")
        else:
            file_bytes = uploaded_file.read()
            extracted_payload = None

            text_probe = file_bytes.decode('utf-8', errors='ignore')
            
            # DOC wrapper check
            doc_match = re.search(r'<!--STEGO_DATA_START:data:image/png;base64,(.*?):STEGO_DATA_END-->', text_probe)
            if doc_match:
                try:
                    img_data = base64.b64decode(doc_match.group(1))
                    img = Image.open(io.BytesIO(img_data)).convert("RGBA")
                    extracted_payload = extract_lsb(img)
                except Exception:
                    pass
            
            # JPG trailer check
            if not extracted_payload:
                jpg_match = re.search(r'<!--STEGO_BACKUP:(.*?)-->', text_probe)
                if jpg_match:
                    extracted_payload = jpg_match.group(1)

            # PDF trailer check
            if not extracted_payload:
                pdf_match = re.search(r'%STEGO_BACKUP:(.*?)$', text_probe)
                if pdf_match:
                    extracted_payload = pdf_match.group(1)

            # Direct LSB read
            if not extracted_payload:
                try:
                    img = Image.open(io.BytesIO(file_bytes)).convert("RGBA")
                    extracted_payload = extract_lsb(img)
                except Exception:
                    pass

            if extracted_payload:
                result = decode_payload(extracted_payload, passkey_dec)
                if result == "WRONG_KEY":
                    st.error("🚫 Wrong encryption key!")
                elif result == "INVALID_PAYLOAD":
                    st.error("⚠️ Payload framing damaged.")
                else:
                    st.success("🔓 Decryption Complete")
                    st.text_area("DECRYPTED MESSAGE", value=result, height=140)
            else:
                st.error("[ERROR] No hidden payload found in this file.")

st.markdown("""
<div class="psx-footer">
    Since different platforms compresses the files , you can choose between different options.
</div>
""", unsafe_allow_html=True)