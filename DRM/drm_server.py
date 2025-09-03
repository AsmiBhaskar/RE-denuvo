import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64
import sqlite3
import os

app = Flask(__name__)

# Server configuration
SERVER_SECRET = b"DRM_SERVER_SECRET_KEY_CHANGE_IN_PRODUCTION_2024"
TOKEN_VALIDITY_HOURS = 24
GRACE_PERIOD_HOURS = 72

class DRMServer:
    def __init__(self, db_path="drm_licenses.db"):
        self.db_path = db_path
        self.setup_database()
        self.setup_crypto()
    
    def setup_crypto(self):
        """Setup cryptographic keys"""
        # RSA key pair for signing tokens
        if not os.path.exists("server_private.pem"):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Save private key
            with open("server_private.pem", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Save public key
            public_key = private_key.public_key()
            with open("server_public.pem", "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
        
        # Load private key
        with open("server_private.pem", "rb") as f:
            self.private_key = load_pem_private_key(f.read(), password=None)
        
        # Symmetric encryption for tokens
        self.fernet = Fernet(base64.urlsafe_b64encode(SERVER_SECRET[:32]))
    
    def setup_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Licenses table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                hardware_fingerprint TEXT,
                user_id TEXT,
                product_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                max_activations INTEGER DEFAULT 1,
                current_activations INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Activation history
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT,
                hardware_fingerprint TEXT,
                ip_address TEXT,
                activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (license_key) REFERENCES licenses (license_key)
            )
        ''')
        
        # Tokens table (for tracking issued tokens)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE,
                license_key TEXT,
                hardware_fingerprint TEXT,
                issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_revoked BOOLEAN DEFAULT 0,
                FOREIGN KEY (license_key) REFERENCES licenses (license_key)
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Add some demo licenses
        self.add_demo_licenses()
    
    def add_demo_licenses(self):
        """Add demo licenses for testing"""
        demo_licenses = [
            {
                "license_key": "DEMO-1234-5678-ABCD-EFGH",
                "user_id": "demo_user_1",
                "product_id": "TEST_PRODUCT",
                "expires_at": datetime.now() + timedelta(days=30),
                "max_activations": 2
            },
            {
                "license_key": "DEMO-9999-8888-7777-6666",
                "user_id": "demo_user_2", 
                "product_id": "TEST_PRODUCT",
                "expires_at": datetime.now() + timedelta(days=365),
                "max_activations": 1
            }
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for license_data in demo_licenses:
            cursor.execute('''
                INSERT OR IGNORE INTO licenses 
                (license_key, user_id, product_id, expires_at, max_activations)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                license_data["license_key"],
                license_data["user_id"],
                license_data["product_id"],
                license_data["expires_at"],
                license_data["max_activations"]
            ))
        
        conn.commit()
        conn.close()
    
    def calculate_hardware_fingerprint(self, client_data):
        """Calculate standardized hardware fingerprint"""
        # Combine hardware identifiers
        fingerprint_data = {
            "cpu_id": client_data.get("cpu_id", ""),
            "motherboard_id": client_data.get("motherboard_id", ""),
            "disk_serial": client_data.get("disk_serial", ""),
            "mac_address": client_data.get("mac_address", ""),
        }
        
        # Create hash
        combined = "|".join(f"{k}:{v}" for k, v in sorted(fingerprint_data.items()))
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def validate_license_key(self, license_key):
        """Validate license key format and existence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT license_key, expires_at, max_activations, current_activations, is_active
            FROM licenses 
            WHERE license_key = ?
        ''', (license_key,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return False, "Invalid license key"
        
        license_key, expires_at, max_activations, current_activations, is_active = result
        
        if not is_active:
            return False, "License has been deactivated"
        
        if expires_at:
            expiry_date = datetime.fromisoformat(expires_at)
            if expiry_date < datetime.now():
                return False, "License has expired"
        
        return True, "License key is valid"
    
    def check_hardware_binding(self, license_key, hardware_fingerprint):
        """Check if hardware can be bound to this license"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get license info
        cursor.execute('''
            SELECT max_activations, current_activations 
            FROM licenses 
            WHERE license_key = ?
        ''', (license_key,))
        
        license_info = cursor.fetchone()
        if not license_info:
            conn.close()
            return False, "License not found"
        
        max_activations, current_activations = license_info
        
        # Check if this hardware is already activated
        cursor.execute('''
            SELECT COUNT(*) FROM activations 
            WHERE license_key = ? AND hardware_fingerprint = ?
        ''', (license_key, hardware_fingerprint))
        
        existing_activation = cursor.fetchone()[0]
        
        if existing_activation > 0:
            # Update last seen
            cursor.execute('''
                UPDATE activations 
                SET last_seen = CURRENT_TIMESTAMP 
                WHERE license_key = ? AND hardware_fingerprint = ?
            ''', (license_key, hardware_fingerprint))
            conn.commit()
            conn.close()
            return True, "Hardware already activated"
        
        # Check if we can add new activation
        if current_activations >= max_activations:
            conn.close()
            return False, f"Maximum activations ({max_activations}) reached"
        
        # Add new activation
        cursor.execute('''
            INSERT INTO activations (license_key, hardware_fingerprint, ip_address)
            VALUES (?, ?, ?)
        ''', (license_key, hardware_fingerprint, request.remote_addr))
        
        cursor.execute('''
            UPDATE licenses 
            SET current_activations = current_activations + 1,
                hardware_fingerprint = ?
            WHERE license_key = ?
        ''', (hardware_fingerprint, license_key))
        
        conn.commit()
        conn.close()
        
        return True, "Hardware activated successfully"
    
    def generate_token(self, license_key, hardware_fingerprint):
        """Generate encrypted token for client"""
        # Token payload
        token_data = {
            "license_key": license_key,
            "hardware_fingerprint": hardware_fingerprint,
            "issued_at": int(time.time()),
            "expires_at": int(time.time()) + (TOKEN_VALIDITY_HOURS * 3600),
            "server_id": "DRM_SERVER_V1",
            "nonce": uuid.uuid4().hex
        }
        
        # Encrypt token
        token_json = json.dumps(token_data)
        encrypted_token = self.fernet.encrypt(token_json.encode())
        
        # Sign token with RSA
        signature = self.private_key.sign(
            encrypted_token,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Combine token and signature
        final_token = {
            "token": base64.b64encode(encrypted_token).decode(),
            "signature": base64.b64encode(signature).decode(),
            "expires_at": token_data["expires_at"]
        }
        
        # Store token hash in database
        token_hash = hashlib.sha256(encrypted_token).hexdigest()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO tokens (token_hash, license_key, hardware_fingerprint, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (
            token_hash, 
            license_key, 
            hardware_fingerprint,
            datetime.fromtimestamp(token_data["expires_at"])
        ))
        
        conn.commit()
        conn.close()
        
        return final_token

# Initialize DRM server
drm_server = DRMServer()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0"
    })

@app.route('/activate', methods=['POST'])
def activate_license():
    """Activate a license for specific hardware"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        license_key = data.get("license_key")
        hardware_data = data.get("hardware_data", {})
        
        if not license_key:
            return jsonify({"error": "License key required"}), 400
        
        # Validate license key
        is_valid, message = drm_server.validate_license_key(license_key)
        if not is_valid:
            return jsonify({"error": message}), 400
        
        # Calculate hardware fingerprint
        hardware_fingerprint = drm_server.calculate_hardware_fingerprint(hardware_data)
        
        # Check hardware binding
        can_bind, bind_message = drm_server.check_hardware_binding(license_key, hardware_fingerprint)
        if not can_bind:
            return jsonify({"error": bind_message}), 400
        
        # Generate token
        token = drm_server.generate_token(license_key, hardware_fingerprint)
        
        return jsonify({
            "success": True,
            "message": bind_message,
            "token": token["token"],
            "signature": token["signature"],
            "expires_at": token["expires_at"],
            "grace_period_hours": GRACE_PERIOD_HOURS
        })
        
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/validate', methods=['POST'])
def validate_token():
    """Validate an existing token"""
    try:
        data = request.get_json()
        token_data = data.get("token")
        signature_data = data.get("signature")
        hardware_data = data.get("hardware_data", {})
        
        if not token_data or not signature_data:
            return jsonify({"valid": False, "error": "Token and signature required"}), 400
        
        # Decode token and signature
        encrypted_token = base64.b64decode(token_data.encode())
        signature = base64.b64decode(signature_data.encode())
        
        # Verify signature
        try:
            drm_server.private_key.public_key().verify(
                signature,
                encrypted_token,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except:
            return jsonify({"valid": False, "error": "Invalid signature"}), 400
        
        # Decrypt token
        try:
            decrypted_data = drm_server.fernet.decrypt(encrypted_token)
            token_payload = json.loads(decrypted_data.decode())
        except:
            return jsonify({"valid": False, "error": "Invalid token"}), 400
        
        # Check expiration
        if token_payload["expires_at"] < int(time.time()):
            return jsonify({"valid": False, "error": "Token expired"}), 400
        
        # Verify hardware fingerprint
        current_fingerprint = drm_server.calculate_hardware_fingerprint(hardware_data)
        if current_fingerprint != token_payload["hardware_fingerprint"]:
            return jsonify({"valid": False, "error": "Hardware mismatch"}), 400
        
        # Check if token is revoked
        token_hash = hashlib.sha256(encrypted_token).hexdigest()
        conn = sqlite3.connect(drm_server.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT is_revoked FROM tokens WHERE token_hash = ?
        ''', (token_hash,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            return jsonify({"valid": False, "error": "Token revoked"}), 400
        
        return jsonify({
            "valid": True,
            "license_key": token_payload["license_key"],
            "expires_at": token_payload["expires_at"]
        })
        
    except Exception as e:
        return jsonify({"valid": False, "error": f"Validation error: {str(e)}"}), 500

@app.route('/revoke', methods=['POST'])
def revoke_license():
    """Revoke a license (admin endpoint)"""
    data = request.get_json()
    license_key = data.get("license_key")
    admin_key = data.get("admin_key")
    
    # Simple admin authentication (use proper auth in production)
    if admin_key != "ADMIN_SECRET_KEY":
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = sqlite3.connect(drm_server.db_path)
    cursor = conn.cursor()
    
    # Deactivate license
    cursor.execute('''
        UPDATE licenses SET is_active = 0 WHERE license_key = ?
    ''', (license_key,))
    
    # Revoke all tokens for this license
    cursor.execute('''
        UPDATE tokens SET is_revoked = 1 WHERE license_key = ?
    ''', (license_key,))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "License revoked"})

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get server statistics (admin endpoint)"""
    conn = sqlite3.connect(drm_server.db_path)
    cursor = conn.cursor()
    
    # Get statistics
    cursor.execute('SELECT COUNT(*) FROM licenses')
    total_licenses = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM licenses WHERE is_active = 1')
    active_licenses = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM activations')
    total_activations = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM tokens WHERE is_revoked = 0')
    active_tokens = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        "total_licenses": total_licenses,
        "active_licenses": active_licenses,
        "total_activations": total_activations,
        "active_tokens": active_tokens,
        "server_time": datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("🔒 DRM License Server Starting...")
    print("📋 Demo License Keys:")
    print("   DEMO-1234-5678-ABCD-EFGH (2 activations)")
    print("   DEMO-9999-8888-7777-6666 (1 activation)")
    print("\n🌐 Server running on http://localhost:5000")
    print("🔍 Health check: http://localhost:5000/health")
    print("📊 Stats: http://localhost:5000/stats")
    
    app.run(debug=True, host='0.0.0.0', port=5000)