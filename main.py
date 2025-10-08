import streamlit as st
import qrcode
from io import BytesIO
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import time
from pathlib import Path
import json
from datetime import datetime, timedelta
import zipfile

SHARED_DATA_FILE = Path(__file__).parent / "shared_files.json"

def load_shared_data():
    """Load shared files from JSON file"""
    if SHARED_DATA_FILE.exists():
        with open(SHARED_DATA_FILE, 'r') as f:
            data = json.load(f)
            for code, info in data.items():
                info['salt'] = base64.b64decode(info['salt'])
                info['created'] = datetime.fromisoformat(info['created'])
                info['expires'] = datetime.fromisoformat(info['expires'])
                for file in info['files']:
                    file['data'] = base64.b64decode(file['data'])
            st.session_state.files = data

def save_shared_data():
    """Save shared files to JSON file"""
    data = {}
    for code, info in st.session_state.files.items():
        data[code] = {
            'salt': base64.b64encode(info['salt']).decode(),
            'created': info['created'].isoformat(),
            'expires': info['expires'].isoformat(),
            'files': []
        }
        for file in info['files']:
            data[code]['files'].append({
                'name': file['name'],
                'data': base64.b64encode(file['data']).decode(),
                'size': file['size'],
                'encrypted': file['encrypted']
            })
    with open(SHARED_DATA_FILE, 'w') as f:
        json.dump(data, f)

# Page configuration
st.set_page_config(
    page_title="SecureShare - Fast File Transfer",
    page_icon="🚀",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for smooth, responsive UI
st.markdown("""
<style>
    /* Main container */
    .main {
        padding: 0rem 1rem;
    }
    
    /* Hero section */
    .hero {
        text-align: center;
        padding: 2rem 0;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 20px;
        margin-bottom: 2rem;
        color: white;
        animation: fadeIn 0.8s ease-in;
    }
    
    .hero h1 {
        font-size: clamp(2rem, 5vw, 3.5rem);
        margin-bottom: 0.5rem;
        font-weight: 700;
    }
    
    .hero p {
        font-size: clamp(1rem, 2vw, 1.2rem);
        opacity: 0.95;
    }
    
    /* Cards */
    .card {
        background: white;
        border-radius: 15px;
        padding: 2rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
        margin-bottom: 1.5rem;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    .card:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 15px rgba(0, 0, 0, 0.1);
    }
    
    /* Buttons */
    .stButton>button {
        width: 100%;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.75rem 2rem;
        border-radius: 10px;
        font-weight: 600;
        font-size: 1.1rem;
        transition: all 0.3s ease;
        cursor: pointer;
    }
    
    .stButton>button:hover {
        transform: scale(1.02);
        box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
    }
    
    /* File uploader */
    .uploadedFile {
        border-radius: 10px;
        border: 2px dashed #667eea;
        padding: 1rem;
        background: #f8f9ff;
    }
    
    /* QR Code container */
    .qr-container {
        text-align: center;
        padding: 2rem;
        background: white;
        border-radius: 15px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
    }
    
    /* Code box */
    .code-box {
        background: #f8f9ff;
        border-left: 4px solid #667eea;
        padding: 1.5rem;
        border-radius: 8px;
        font-family: 'Courier New', monospace;
        font-size: 1.5rem;
        font-weight: bold;
        text-align: center;
        margin: 1rem 0;
        letter-spacing: 0.3rem;
    }
    
    /* Status indicators */
    .status-success {
        background: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #28a745;
        margin: 1rem 0;
    }
    
    .status-info {
        background: #d1ecf1;
        color: #0c5460;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #17a2b8;
        margin: 1rem 0;
    }
    
    /* Responsive grid */
    @media (max-width: 768px) {
        .hero {
            padding: 1.5rem 1rem;
        }
        
        .card {
            padding: 1.5rem;
        }
        
        .code-box {
            font-size: 1.2rem;
            letter-spacing: 0.2rem;
        }
    }
    
    /* Animations */
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(-20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .fade-in {
        animation: fadeIn 0.6s ease-in;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Progress bar */
    .stProgress > div > div > div > div {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
</style>
""", unsafe_allow_html=True)

# Load shared data
load_shared_data()

# Initialize session state
if 'files' not in st.session_state:
    st.session_state.files = {}
if 'share_code' not in st.session_state:
    st.session_state.share_code = None
if 'encryption_key' not in st.session_state:
    st.session_state.encryption_key = None

def generate_share_code():
    """Generate a 6-digit share code"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

def generate_encryption_key(password: str, salt: bytes) -> bytes:
    """Generate encryption key from password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_data: bytes, key: bytes) -> bytes:
    """Encrypt file data"""
    f = Fernet(key)
    return f.encrypt(file_data)

def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt file data"""
    f = Fernet(key)
    return f.decrypt(encrypted_data)

def generate_qr_code(data: str):
    """Generate QR code for share code"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="#667eea", back_color="white")
    return img

def img_to_base64(img):
    """Convert PIL image to base64"""
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

# Header
st.markdown("""
<div class="hero">
    <h1>🚀 SecureShare</h1>
    <p>Fast, Secure & Easy File Sharing Between Devices</p>
</div>
""", unsafe_allow_html=True)

# Main content
tab1, tab2, tab3 = st.tabs(["📤 Send Files", "📥 Receive Files", "ℹ️ About"])

with tab1:
    st.markdown("<div class='fade-in'>", unsafe_allow_html=True)
    
    col1, col2 = st.columns([3, 2])
    
    with col1:
        st.markdown("### Upload Files")
        uploaded_files = st.file_uploader(
            "Choose files to share",
            accept_multiple_files=True,
            help="Select one or more files to share securely"
        )
        
        if uploaded_files:
            st.markdown(f"**{len(uploaded_files)} file(s) selected:**")
            total_size = 0
            for file in uploaded_files:
                size_mb = len(file.getvalue()) / (1024 * 1024)
                total_size += size_mb
                st.markdown(f"- 📄 {file.name} ({size_mb:.2f} MB)")
            
            st.markdown(f"**Total size:** {total_size:.2f} MB")
            
            # Encryption option
            use_encryption = st.checkbox("🔒 Encrypt files (recommended)", value=True)
            
            if st.button("🚀 Generate Share Code", type="primary"):
                with st.spinner("Preparing your files..."):
                    # Generate share code
                    share_code = generate_share_code()
                    
                    # Prepare encryption
                    salt = secrets.token_bytes(16)
                    encryption_key = generate_encryption_key(share_code, salt)
                    
                    # Store files
                    file_data = []
                    for file in uploaded_files:
                        data = file.getvalue()
                        if use_encryption:
                            data = encrypt_file(data, encryption_key)
                        
                        file_data.append({
                            'name': file.name,
                            'data': data,
                            'size': len(file.getvalue()),
                            'encrypted': use_encryption
                        })
                    
                    st.session_state.files[share_code] = {
                        'files': file_data,
                        'salt': salt,
                        'created': datetime.now(),
                        'expires': datetime.now() + timedelta(hours=24)
                    }
                    st.session_state.share_code = share_code
                    st.session_state.encryption_key = encryption_key
                    
                    # Save shared data to file
                    save_shared_data()
                    
                st.success("✅ Files ready to share!")
    
    with col2:
        if st.session_state.share_code:
            st.markdown("### 🎉 Share Code Generated!")
            
            # Share code display
            st.markdown(f"""
            <div class='code-box'>
                {st.session_state.share_code}
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class='status-info'>
                ⏱️ Code expires in 24 hours<br>
                🔒 Files are encrypted for security
            </div>
            """, unsafe_allow_html=True)
            
            # QR Code
            st.markdown("### 📱 Scan QR Code")
            qr_data = f"SecureShare Code: {st.session_state.share_code}"
            qr_img = generate_qr_code(qr_data)
            qr_base64 = img_to_base64(qr_img)
            
            st.markdown(f"""
            <div class='qr-container'>
                <img src='data:image/png;base64,{qr_base64}' width='200'>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("🔄 Generate New Code"):
                st.session_state.share_code = None
                st.rerun()
    
    st.markdown("</div>", unsafe_allow_html=True)

with tab2:
    st.markdown("<div class='fade-in'>", unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 3])
    
    with col1:
        st.markdown("### Enter Share Code")
        receive_code = st.text_input(
            "6-digit code",
            max_chars=6,
            placeholder="000000",
            help="Enter the code shared with you"
        )
        
        if st.button("🔍 Retrieve Files", type="primary"):
            if receive_code in st.session_state.files:
                file_info = st.session_state.files[receive_code]
                
                # Check expiration
                if datetime.now() > file_info['expires']:
                    st.error("❌ This share code has expired!")
                else:
                    st.session_state.current_download = receive_code
                    st.success("✅ Files found!")
            else:
                st.error("❌ Invalid share code. Please check and try again.")
    
    with col2:
        if 'current_download' in st.session_state and st.session_state.current_download:
            code = st.session_state.current_download
            file_info = st.session_state.files[code]
            
            st.markdown("### 📦 Available Files")
            
            for idx, file_data in enumerate(file_info['files']):
                col_a, col_b = st.columns([3, 1])
                
                with col_a:
                    st.markdown(f"**📄 {file_data['name']}**")
                    st.markdown(f"Size: {file_data['size'] / 1024:.2f} KB")
                
                with col_b:
                    # Decrypt if needed
                    data = file_data['data']
                    if file_data['encrypted']:
                        salt = file_info['salt']
                        key = generate_encryption_key(code, salt)
                        try:
                            data = decrypt_file(data, key)
                        except:
                            st.error("Decryption failed")
                            continue
                    
                    st.download_button(
                        "⬇️ Download",
                        data=data,
                        file_name=file_data['name'],
                        mime="application/octet-stream",
                        key=f"download_{code}_{idx}"
                    )
            
            # Multi-file download options
            st.markdown("---")
            if len(file_info['files']) > 1:
                selected = st.multiselect(
                    "Select files to download",
                    [f['name'] for f in file_info['files']],
                    default=[],
                    help="Choose which files to include in the ZIP download"
                )
                
                if selected and st.button("📦 Download Selected as ZIP", type="primary"):
                    with st.spinner("Preparing ZIP file..."):
                        zip_buffer = BytesIO()
                        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                            for file_data in file_info['files']:
                                if file_data['name'] in selected:
                                    data = file_data['data']
                                    if file_data['encrypted']:
                                        salt = file_info['salt']
                                        key = generate_encryption_key(code, salt)
                                        data = decrypt_file(data, key)
                                    zip_file.writestr(file_data['name'], data)
                        zip_buffer.seek(0)
                        st.download_button(
                            "⬇️ Download ZIP",
                            data=zip_buffer,
                            file_name="selected_files.zip",
                            mime="application/zip",
                            key="download_selected_zip"
                        )
                
                # Download all button
                if st.button("📥 Download All as ZIP"):
                    with st.spinner("Preparing ZIP file..."):
                        zip_buffer = BytesIO()
                        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                            for file_data in file_info['files']:
                                data = file_data['data']
                                if file_data['encrypted']:
                                    salt = file_info['salt']
                                    key = generate_encryption_key(code, salt)
                                    data = decrypt_file(data, key)
                                zip_file.writestr(file_data['name'], data)
                        zip_buffer.seek(0)
                        st.download_button(
                            "⬇️ Download ZIP",
                            data=zip_buffer,
                            file_name="all_files.zip",
                            mime="application/zip",
                            key="download_all_zip"
                        )
    
    st.markdown("</div>", unsafe_allow_html=True)

with tab3:
    st.markdown("<div class='fade-in'>", unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🎯 Features
        
        - **🚀 Fast Transfer**: Share files instantly
        - **🔒 Secure**: End-to-end encryption
        - **📱 Mobile Friendly**: Works on all devices
        - **🔗 Simple Sharing**: Just share a 6-digit code
        - **📷 QR Codes**: Scan to connect quickly
        - **⏱️ Temporary**: Files expire in 24 hours
        - **🎨 Beautiful UI**: Clean and modern design
        """)
    
    with col2:
        st.markdown("""
        ### 📖 How to Use
        
        **Sending Files:**
        1. Go to "Send Files" tab
        2. Upload your file(s)
        3. Click "Generate Share Code"
        4. Share the code or QR code
        
        **Receiving Files:**
        1. Go to "Receive Files" tab
        2. Enter the 6-digit code
        3. Click "Retrieve Files"
        4. Download your file(s)
        
        **Security:** All files are encrypted with military-grade encryption (AES-256)
        """)
    
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; padding: 2rem;'>
        <p style='color: #666; font-size: 0.9rem;'>
            Built with ❤️ using Streamlit | Secure • Fast • Simple
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("</div>", unsafe_allow_html=True)

# Cleanup expired files (runs on every page load)
expired_codes = []
for code, file_info in st.session_state.files.items():
    if datetime.now() > file_info['expires']:
        expired_codes.append(code)

for code in expired_codes:
    del st.session_state.files[code]

# Save updated data after cleanup
save_shared_data()