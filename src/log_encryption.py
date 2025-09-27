"""
Log Encryption Module
Provides encryption/decryption capabilities for log files to ensure integrity and confidentiality.
"""

import os
import base64
import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Any, Union, Tuple, List
from datetime import datetime
import getpass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend


class LogEncryption:
    """Handles encryption and decryption of log files."""
    
    def __init__(self, 
                 encryption_method: str = "symmetric",  # symmetric, asymmetric
                 key_file: Optional[str] = None,
                 password: Optional[str] = None):
        
        self.encryption_method = encryption_method
        self.key_file = Path(key_file) if key_file else None
        self.password = password
        self._cipher = None
        self._private_key = None
        self._public_key = None
        
        print(f"🔐 Log Encryption initialized")
        print(f"   Method: {encryption_method}")
        
        if encryption_method == "symmetric":
            self._setup_symmetric_encryption()
        elif encryption_method == "asymmetric":
            self._setup_asymmetric_encryption()
    
    def _setup_symmetric_encryption(self):
        """Set up symmetric encryption using Fernet."""
        if self.key_file and self.key_file.exists():
            # Load existing key
            try:
                with open(self.key_file, 'rb') as f:
                    key_data = json.load(f)
                
                if self.password:
                    # Decrypt the stored key
                    encrypted_key = base64.b64decode(key_data['encrypted_key'])
                    salt = base64.b64decode(key_data['salt'])
                    key = self._derive_key_from_password(self.password, salt)
                    f = Fernet(key)
                    actual_key = f.decrypt(encrypted_key)
                    self._cipher = Fernet(actual_key)
                else:
                    # Use key directly
                    self._cipher = Fernet(key_data['key'].encode())
                
                print("✅ Loaded existing encryption key")
                
            except Exception as e:
                print(f"❌ Failed to load encryption key: {e}")
                raise
        
        else:
            # Generate new key
            key = Fernet.generate_key()
            self._cipher = Fernet(key)
            
            # Save key to file
            if self.key_file:
                self.key_file.parent.mkdir(exist_ok=True)
                
                key_data = {
                    'created': datetime.now().isoformat(),
                    'method': 'symmetric'
                }
                
                if self.password:
                    # Encrypt the key with password
                    salt = os.urandom(16)
                    password_key = self._derive_key_from_password(self.password, salt)
                    f = Fernet(password_key)
                    encrypted_key = f.encrypt(key)
                    
                    key_data.update({
                        'encrypted_key': base64.b64encode(encrypted_key).decode(),
                        'salt': base64.b64encode(salt).decode(),
                        'encrypted': True
                    })
                else:
                    key_data.update({
                        'key': key.decode(),
                        'encrypted': False
                    })
                
                with open(self.key_file, 'w') as f:
                    json.dump(key_data, f, indent=2)
                
                print(f"💾 Saved encryption key to {self.key_file}")
    
    def _setup_asymmetric_encryption(self):
        """Set up asymmetric encryption using RSA."""
        if self.key_file and self.key_file.exists():
            # Load existing key pair
            try:
                with open(self.key_file, 'rb') as f:
                    key_data = json.load(f)
                
                private_key_pem = base64.b64decode(key_data['private_key'])
                public_key_pem = base64.b64decode(key_data['public_key'])
                
                if self.password:
                    self._private_key = serialization.load_pem_private_key(
                        private_key_pem,
                        password=self.password.encode(),
                        backend=default_backend()
                    )
                else:
                    self._private_key = serialization.load_pem_private_key(
                        private_key_pem,
                        password=None,
                        backend=default_backend()
                    )
                
                self._public_key = serialization.load_pem_public_key(
                    public_key_pem,
                    backend=default_backend()
                )
                
                print("✅ Loaded existing RSA key pair")
                
            except Exception as e:
                print(f"❌ Failed to load RSA keys: {e}")
                raise
        
        else:
            # Generate new key pair
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self._public_key = self._private_key.public_key()
            
            # Save key pair to file
            if self.key_file:
                self.key_file.parent.mkdir(exist_ok=True)
                
                # Serialize keys
                if self.password:
                    private_pem = self._private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.BestAvailableEncryption(
                            self.password.encode()
                        )
                    )
                else:
                    private_pem = self._private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                
                public_pem = self._public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                key_data = {
                    'created': datetime.now().isoformat(),
                    'method': 'asymmetric',
                    'private_key': base64.b64encode(private_pem).decode(),
                    'public_key': base64.b64encode(public_pem).decode(),
                    'encrypted': bool(self.password)
                }
                
                with open(self.key_file, 'w') as f:
                    json.dump(key_data, f, indent=2)
                
                print(f"💾 Saved RSA key pair to {self.key_file}")
    
    def _derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt_data(self, data: Union[str, bytes]) -> bytes:
        """Encrypt data using the configured method."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if self.encryption_method == "symmetric":
            return self._cipher.encrypt(data)
        
        elif self.encryption_method == "asymmetric":
            # For large data, use hybrid encryption (RSA + AES)
            return self._hybrid_encrypt(data)
        
        else:
            raise ValueError(f"Unsupported encryption method: {self.encryption_method}")
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using the configured method."""
        if self.encryption_method == "symmetric":
            return self._cipher.decrypt(encrypted_data)
        
        elif self.encryption_method == "asymmetric":
            return self._hybrid_decrypt(encrypted_data)
        
        else:
            raise ValueError(f"Unsupported encryption method: {self.encryption_method}")
    
    def _hybrid_encrypt(self, data: bytes) -> bytes:
        """Hybrid encryption: RSA for AES key, AES for data."""
        # Generate AES key
        aes_key = Fernet.generate_key()
        aes_cipher = Fernet(aes_key)
        
        # Encrypt data with AES
        encrypted_data = aes_cipher.encrypt(data)
        
        # Encrypt AES key with RSA
        encrypted_aes_key = self._public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine encrypted key and data
        result = {
            'encrypted_key': base64.b64encode(encrypted_aes_key).decode(),
            'encrypted_data': base64.b64encode(encrypted_data).decode()
        }
        
        return json.dumps(result).encode('utf-8')
    
    def _hybrid_decrypt(self, encrypted_data: bytes) -> bytes:
        """Hybrid decryption: RSA for AES key, AES for data."""
        try:
            data = json.loads(encrypted_data.decode('utf-8'))
            
            # Decrypt AES key with RSA
            encrypted_aes_key = base64.b64decode(data['encrypted_key'])
            aes_key = self._private_key.decrypt(
                encrypted_aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt data with AES
            aes_cipher = Fernet(aes_key)
            encrypted_data_bytes = base64.b64decode(data['encrypted_data'])
            return aes_cipher.decrypt(encrypted_data_bytes)
            
        except Exception as e:
            raise ValueError(f"Failed to decrypt data: {e}")
    
    def encrypt_file(self, input_file: Union[str, Path], output_file: Union[str, Path] = None) -> bool:
        """Encrypt a file."""
        input_path = Path(input_file)
        if not input_path.exists():
            print(f"❌ Input file not found: {input_path}")
            return False
        
        if output_file is None:
            output_path = input_path.with_suffix(input_path.suffix + '.enc')
        else:
            output_path = Path(output_file)
        
        try:
            with open(input_path, 'rb') as f:
                data = f.read()
            
            encrypted_data = self.encrypt_data(data)
            
            # Create metadata
            metadata = {
                'original_filename': input_path.name,
                'encrypted_at': datetime.now().isoformat(),
                'encryption_method': self.encryption_method,
                'file_hash': hashlib.sha256(data).hexdigest()
            }
            
            # Write encrypted file with metadata
            with open(output_path, 'wb') as f:
                # Write metadata length (4 bytes)
                metadata_json = json.dumps(metadata).encode('utf-8')
                f.write(len(metadata_json).to_bytes(4, 'big'))
                f.write(metadata_json)
                f.write(encrypted_data)
            
            print(f"✅ Encrypted file: {input_path} → {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to encrypt file {input_path}: {e}")
            return False
    
    def decrypt_file(self, input_file: Union[str, Path], output_file: Union[str, Path] = None) -> bool:
        """Decrypt a file."""
        input_path = Path(input_file)
        if not input_path.exists():
            print(f"❌ Input file not found: {input_path}")
            return False
        
        try:
            with open(input_path, 'rb') as f:
                # Read metadata
                metadata_length = int.from_bytes(f.read(4), 'big')
                metadata_json = f.read(metadata_length)
                metadata = json.loads(metadata_json.decode('utf-8'))
                
                # Read encrypted data
                encrypted_data = f.read()
            
            decrypted_data = self.decrypt_data(encrypted_data)
            
            # Verify file integrity
            computed_hash = hashlib.sha256(decrypted_data).hexdigest()
            if computed_hash != metadata['file_hash']:
                print("⚠️  Warning: File integrity check failed")
            
            # Determine output file
            if output_file is None:
                output_path = input_path.with_suffix('')  # Remove .enc extension
                if output_path.suffix == '':
                    output_path = output_path.with_name(metadata.get('original_filename', 'decrypted_file'))
            else:
                output_path = Path(output_file)
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"✅ Decrypted file: {input_path} → {output_path}")
            print(f"   Original: {metadata.get('original_filename', 'unknown')}")
            print(f"   Encrypted at: {metadata.get('encrypted_at', 'unknown')}")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to decrypt file {input_path}: {e}")
            return False
    
    def get_key_info(self) -> Dict[str, Any]:
        """Get information about the encryption key."""
        if self.key_file and self.key_file.exists():
            try:
                with open(self.key_file, 'r') as f:
                    key_data = json.load(f)
                
                return {
                    'key_file': str(self.key_file),
                    'method': key_data.get('method', 'unknown'),
                    'created': key_data.get('created', 'unknown'),
                    'encrypted': key_data.get('encrypted', False)
                }
            except Exception:
                return {'error': 'Failed to read key file'}
        
        return {
            'key_file': 'None',
            'method': self.encryption_method,
            'status': 'In-memory only'
        }


class EncryptedLogger:
    """Logger that automatically encrypts log entries."""
    
    def __init__(self, 
                 log_file: Union[str, Path],
                 encryption: LogEncryption,
                 buffer_size: int = 1000):
        
        self.log_file = Path(log_file)
        self.encryption = encryption
        self.buffer_size = buffer_size
        self.buffer = []
        
        # Ensure log directory exists
        self.log_file.parent.mkdir(exist_ok=True)
        
        print(f"🔐 Encrypted Logger initialized: {self.log_file.name}")
    
    def log(self, data: Dict[str, Any]):
        """Add a log entry to the buffer."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        
        self.buffer.append(log_entry)
        
        if len(self.buffer) >= self.buffer_size:
            self.flush()
    
    def flush(self):
        """Write buffered logs to encrypted file."""
        if not self.buffer:
            return
        
        try:
            # Prepare log data
            log_data = {
                'entries': self.buffer,
                'count': len(self.buffer),
                'flushed_at': datetime.now().isoformat()
            }
            
            log_json = json.dumps(log_data, ensure_ascii=False)
            encrypted_data = self.encryption.encrypt_data(log_json)
            
            # Append to encrypted log file
            with open(self.log_file, 'ab') as f:
                # Write entry size (4 bytes) + encrypted data
                f.write(len(encrypted_data).to_bytes(4, 'big'))
                f.write(encrypted_data)
            
            print(f"💾 Flushed {len(self.buffer)} encrypted log entries")
            self.buffer.clear()
            
        except Exception as e:
            print(f"❌ Failed to flush encrypted logs: {e}")
    
    def read_logs(self, limit: int = 100) -> List[Dict]:
        """Read and decrypt log entries."""
        if not self.log_file.exists():
            return []
        
        entries = []
        
        try:
            with open(self.log_file, 'rb') as f:
                while True and len(entries) < limit:
                    # Read entry size
                    size_bytes = f.read(4)
                    if len(size_bytes) < 4:
                        break
                    
                    entry_size = int.from_bytes(size_bytes, 'big')
                    encrypted_data = f.read(entry_size)
                    
                    if len(encrypted_data) < entry_size:
                        break
                    
                    # Decrypt and parse
                    decrypted_data = self.encryption.decrypt_data(encrypted_data)
                    log_data = json.loads(decrypted_data.decode('utf-8'))
                    
                    entries.extend(log_data.get('entries', []))
            
            # Return most recent entries
            return entries[-limit:] if entries else []
            
        except Exception as e:
            print(f"❌ Failed to read encrypted logs: {e}")
            return []
    
    def close(self):
        """Close the logger and flush remaining data."""
        self.flush()


def setup_encryption(key_file: str = None, method: str = "symmetric") -> LogEncryption:
    """Interactive setup for log encryption."""
    print("🔐 Setting up log encryption...")
    
    if key_file is None:
        key_file = "./config/encryption_key.json"
    
    use_password = input("Use password protection? (y/N): ").lower().startswith('y')
    password = None
    
    if use_password:
        password = getpass.getpass("Enter encryption password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password != confirm_password:
            print("❌ Passwords do not match")
            return None
    
    try:
        encryption = LogEncryption(
            encryption_method=method,
            key_file=key_file,
            password=password
        )
        
        print("✅ Encryption setup completed")
        return encryption
        
    except Exception as e:
        print(f"❌ Failed to setup encryption: {e}")
        return None


def main():
    """Demo function for testing log encryption."""
    print("🧪 Testing log encryption...")
    
    # Test symmetric encryption
    encryption = LogEncryption(
        encryption_method="symmetric",
        key_file="./config/test_key.json"
    )
    
    # Test data encryption
    test_data = "This is sensitive log data that should be encrypted."
    encrypted = encryption.encrypt_data(test_data)
    decrypted = encryption.decrypt_data(encrypted).decode('utf-8')
    
    print(f"Original: {test_data}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_data == decrypted}")
    
    # Test encrypted logger
    encrypted_logger = EncryptedLogger(
        log_file="./logs/encrypted_test.log",
        encryption=encryption,
        buffer_size=3
    )
    
    # Add some test logs
    for i in range(5):
        encrypted_logger.log({
            'event_type': 'test',
            'message': f'Test log entry {i+1}',
            'value': i * 10
        })
    
    # Read back logs
    logs = encrypted_logger.read_logs()
    print(f"\nRead {len(logs)} encrypted log entries:")
    for log in logs:
        print(f"  {log['timestamp']}: {log['data']['message']}")
    
    encrypted_logger.close()
    
    # Show key info
    key_info = encryption.get_key_info()
    print(f"\nKey Info: {json.dumps(key_info, indent=2)}")
    
    print("\n✅ Encryption test completed")


if __name__ == "__main__":
    main()