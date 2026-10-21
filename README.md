iNcreept 👾

A retro steganography web app that hides encrypted messages in images and bypasses social media compression using PDF/DOC wrappers.

📖 Project Overview

iNcreept is a web-based, anti-compression steganography suite. Traditional image steganography breaks when sent over platforms like WhatsApp or Instagram due to lossy image compression (JPEG quantization). iNcreept solves this by encoding data into the Least Significant Bits (LSB) of an image, encrypting it with a SHA-256 hashed password, and optionally wrapping the output in .PDF or .DOC formats to bypass platform media filters.

🗄️ Dataset

No external dataset is required. This application is designed to process user-supplied cover images (PNG, JPG, WEBP) dynamically.

🛠️ Technologies Used

Language: Python 3

Frontend/Framework: Streamlit (with custom CSS for a retro UI)

Image Processing: Pillow (PIL)

Security/Cryptography: hashlib (SHA-256), Base64, Custom XOR cipher

🚀 Setup & Run Instructions

Clone the repository:

git clone <your-github-repo-link>
cd increept


Install the required dependencies:

pip install -r requirements.txt


Run the application:

streamlit run app.py


Access the web app:
Open your browser and navigate to http://localhost:8501.

🔑 Key Information

Sender: Uploads an image, types a secret message, sets a passkey, and downloads a protected container file.

Receiver: Uploads the received container, inputs the passkey, and decrypts the hidden payload instantly.
