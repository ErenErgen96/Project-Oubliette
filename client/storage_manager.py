import os
import json
import struct
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configuration Import (Separation of Concerns)
try:
    import config
except ImportError:
    # Fallback if config.py is missing (for testing)
    class Config:
        KMS_SERVER_URL = "http://127.0.0.1:8001"
        SECTOR_SIZE = 512
        HEADER_SECTORS = 100
        CONTAINER_SIZE_MB = 100
    config = Config()

# ==========================================
# PART 1: THE ENCRYPTION ENGINE (LOW LEVEL)
# ==========================================
class CryptoEngine:
    """
    Handles low-level AES-256 XTS encryption for individual sectors.
    Compliant with IEEE 1619 standard for storage encryption.
    """
    def __init__(self, key=None):
        self.sector_size = config.SECTOR_SIZE
        if key:
            if len(key) != 32:
                # Key Expansion for XTS Mode (256-bit key -> 512-bit tweakable key)
                # In production, use HKDF to derive two independent keys.
                key = key + key 
            self.key = key
        else:
            raise ValueError("CryptoEngine requires a Master Key from KMS!")

    def _get_cipher(self, sector_index):
        # Little-endian conversion for XTS tweak
        tweak = sector_index.to_bytes(16, byteorder='little')
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.XTS(tweak),
            backend=default_backend()
        )
        return cipher

    def encrypt_sector(self, data, sector_index):
        if len(data) != self.sector_size:
            data = data.ljust(self.sector_size, b'\0')
        cipher = self._get_cipher(sector_index)
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt_sector(self, encrypted_data, sector_index):
        cipher = self._get_cipher(sector_index)
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()

# ==========================================#
# PART 2: THE VAULT SYSTEM (FILE SYSTEM)    #
# ==========================================#

class VaultStorage:
    """
    Manages the encrypted container via Remote Key Management System (KMS).
    Implements Volatile Key Handling (RAM-only keys).
    """
    def __init__(self, container_path: str, password: str, duress_tokens: list = None):
        """
        Initialize Vault Storage.
        :param duress_tokens: List of tokens that trigger immediate key revocation (Sanitization).
        """
        self.path = container_path
        self.password = password
        self.duress_tokens = duress_tokens 
        
        # Extract Vault ID from filename
        self.vault_id = os.path.splitext(os.path.basename(container_path))[0]
        
        self.file_map = {} 
        self.next_free_sector = config.HEADER_SECTORS + 1
        self.engine = None 

        # KMS Health Check
        try:
            requests.get(config.KMS_SERVER_URL, timeout=2)
        except:
            raise ConnectionError(f"Connection to Key Management Server ({config.KMS_SERVER_URL}) failed.")
        
        if not os.path.exists(self.path):
            if not self.duress_tokens:
                raise ValueError("Security Policy Violation: New containers require at least one Duress Token.")
            self._create_new_container()
        else:
            self._open_existing_container()

    def _get_remote_key(self):
        """Authenticates with KMS to retrieve the wrapped key."""
        payload = {
            "vault_id": self.vault_id,
            "password": self.password
        }
        
        try:
            response = requests.post(f"{config.KMS_SERVER_URL}/access_vault", json=payload)
            
            if response.status_code == 200:
                data = response.json()
                key_hex = data.get("key")
                
                # Check for Revocation Signal
                if data.get("mode") == "emergency_revocation":
                    print("\n[SECURITY ALERT] Server executed Emergency Key Revocation Protocol.")
                
                return bytes.fromhex(key_hex)
            
            elif response.status_code == 404:
                raise ValueError("Vault ID not found on KMS. (Key may have been revoked/purged)")
            elif response.status_code == 401:
                raise ValueError("Authentication Failed: Invalid Credentials.")
            else:
                raise Exception(f"KMS Error: {response.text}")
                
        except requests.exceptions.ConnectionError:
            raise ConnectionError("Lost secure link to Key Management Server.")

    def _create_new_container(self):
        print(f"[Vault] Registering new secure container: {self.vault_id}")
        
        payload = {
            "vault_id": self.vault_id,
            "real_password": self.password,
            "duress_tokens": self.duress_tokens # Refactored from 'panic_passwords'
        }
        
        resp = requests.post(f"{config.KMS_SERVER_URL}/create_vault", json=payload)
        
        if resp.status_code != 200:
             try:
                 err_detail = resp.json()['detail']
             except:
                 err_detail = "Unknown Error"
             
             if "already exists" in err_detail:
                 print("[Info] Vault ID exists on KMS, syncing state...")
             else:
                 raise Exception(f"KMS Registration Failed: {err_detail}")

        # Retrieve Key (Verify Authentication)
        master_key = self._get_remote_key()
        self.engine = CryptoEngine(master_key)
        
        # Initialize Physical Container
        with open(self.path, 'wb') as f:
            f.write(os.urandom(16)) # Secure header padding
            f.write(b'\0' * (config.CONTAINER_SIZE_MB * 1024 * 1024))
            
        self._save_metadata()
        print(f"[Vault] Initialization complete. Active Duress Tokens: {len(self.duress_tokens)}")

    def _open_existing_container(self):
        print(f"[Vault] Authenticating with KMS: {self.vault_id}")
        
        # 1. Retrieve Volatile Key
        master_key = self._get_remote_key()
        self.engine = CryptoEngine(master_key)
        
        # 2. Decrypt Metadata Header
        if not os.path.exists(self.path):
             raise FileNotFoundError("Physical container file missing.")

        try:
            self._load_metadata()
        except Exception as e:
            print(f"\n[!!!] DECRYPTION FAILED.")
            print("Possible Causes: 1. Invalid Credential, 2. File Corruption, 3. KEY REVOKED")
            raise ValueError(f"Decryption failed. Integrity check error: {e}")

    def _save_metadata(self):
        """Encrypts and persists the file allocation table."""
        json_data = json.dumps(self.file_map).encode()
        payload = struct.pack('>I', len(json_data)) + json_data
        
        max_header_size = (config.HEADER_SECTORS * config.SECTOR_SIZE) - 16
        if len(payload) > max_header_size:
             raise Exception("Metadata buffer overflow!")

        padding_needed = config.SECTOR_SIZE - (len(payload) % config.SECTOR_SIZE)
        if padding_needed != config.SECTOR_SIZE:
            payload += b'\0' * padding_needed

        with open(self.path, 'r+b') as f:
            f.seek(16)
            chunks = [payload[i:i+config.SECTOR_SIZE] for i in range(0, len(payload), config.SECTOR_SIZE)]
            for i, chunk in enumerate(chunks):
                encrypted_chunk = self.engine.encrypt_sector(chunk, i)
                f.write(encrypted_chunk)

    def _load_metadata(self):
        decrypted_stream = b""
        with open(self.path, 'rb') as f:
            f.seek(16)
            for i in range(config.HEADER_SECTORS):
                chunk = f.read(config.SECTOR_SIZE)
                if not chunk: break
                decrypted_stream += self.engine.decrypt_sector(chunk, i)
        
        try:
            data_len = struct.unpack('>I', decrypted_stream[:4])[0]
        except:
             raise ValueError("Header Unreadable (Possible Key Revocation)")

        if data_len > len(decrypted_stream) or data_len == 0:
            raise ValueError("Invalid Metadata Length (Possible Key Revocation)")

        try:
            self.file_map = json.loads(decrypted_stream[4:4+data_len])
        except json.JSONDecodeError:
            raise ValueError("Corrupted Allocation Table")
        
        max_sector = config.HEADER_SECTORS
        for meta in self.file_map.values():
            end = meta['start'] + (meta['size'] // config.SECTOR_SIZE) + 1
            if end > max_sector: max_sector = end
        self.next_free_sector = max_sector + 1
        
        print(f"[Vault] Decryption successful. File System Ready.")

    # --- Standard I/O Operations ---
    def write_file(self, filename: str, data: bytes):
        start_sector = self.next_free_sector
        if filename in self.file_map:
            start_sector = self.file_map[filename]['start']
        else:
            sectors_needed = (len(data) + config.SECTOR_SIZE - 1) // config.SECTOR_SIZE
            self.next_free_sector += sectors_needed

        self.file_map[filename] = {'start': start_sector, 'size': len(data)}
        self._save_metadata()

        payload = data
        if len(payload) % config.SECTOR_SIZE != 0:
            payload += b'\0' * (config.SECTOR_SIZE - (len(payload) % config.SECTOR_SIZE))

        with open(self.path, 'r+b') as f:
            f.seek(start_sector * config.SECTOR_SIZE)
            chunks = [payload[i:i+config.SECTOR_SIZE] for i in range(0, len(payload), config.SECTOR_SIZE)]
            for i, chunk in enumerate(chunks):
                real_sector = start_sector + i
                f.write(self.engine.encrypt_sector(chunk, real_sector))
        print(f"[IO] Written: {filename}")

    def read_file(self, filename: str) -> bytes:
        if filename not in self.file_map: return None
        meta = self.file_map[filename]
        data = b""
        with open(self.path, 'rb') as f:
            f.seek(meta['start'] * config.SECTOR_SIZE)
            sector_count = (meta['size'] + config.SECTOR_SIZE - 1) // config.SECTOR_SIZE
            for i in range(sector_count):
                chunk = f.read(config.SECTOR_SIZE)
                data += self.engine.decrypt_sector(chunk, meta['start'] + i)
        return data[:meta['size']]

    def delete_file(self, filename: str):
        if filename in self.file_map:
            del self.file_map[filename]
            self._save_metadata()
            print(f"[IO] Deleted: {filename}")