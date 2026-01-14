import sqlite3
import secrets
import json
import logging
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

# Configuration Import
try:
    import config
except ImportError:
    class Config:
        DB_NAME = "secure_keystore.sqlite"
        KMS_SERVER_URL = "http://127.0.0.1:8001"
    config = Config()

# Logging Setup (Kurumsal Loglama)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - KMS - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Oubliette KMS | Enterprise Key Management")

# ==========================================
# DATABASE INITIALIZATION
# ==========================================
def init_db():
    """Initializes the secure keystore with the updated schema."""
    conn = sqlite3.connect(config.DB_NAME)
    c = conn.cursor()
    
    
    c.execute('''CREATE TABLE IF NOT EXISTS secure_containers 
                 (vault_id TEXT PRIMARY KEY, 
                  real_password TEXT, 
                  duress_tokens TEXT, 
                  wrapped_key BLOB)''')
    conn.commit()
    conn.close()
    logger.info("Keystore initialized successfully.")

init_db()

# ==========================================
# DATA MODELS (Pydantic)
# ==========================================
class VaultCreate(BaseModel):
    vault_id: str
    real_password: str
    duress_tokens: list[str] 

class VaultAccess(BaseModel):
    vault_id: str
    password: str

# ==========================================
# API ENDPOINTS
# ==========================================

@app.post("/create_vault")
def create_vault(data: VaultCreate):
    conn = sqlite3.connect(config.DB_NAME)
    c = conn.cursor()
    
    # 256-bit Cryptographic Key Generation
    master_key = secrets.token_bytes(32)
    
    # Store tokens as JSON string
    tokens_json = json.dumps(data.duress_tokens)
    
    try:
        c.execute("INSERT INTO secure_containers VALUES (?, ?, ?, ?)", 
                  (data.vault_id, data.real_password, tokens_json, master_key))
        conn.commit()
        logger.info(f"New container registered: {data.vault_id}")
    except sqlite3.IntegrityError:
        conn.close()
        logger.warning(f"Registration failed: ID {data.vault_id} already exists.")
        raise HTTPException(status_code=400, detail="Container ID already exists in KMS.")
    
    conn.close()
    return {"status": "registered", "vault_id": data.vault_id}

@app.post("/access_vault")
def access_vault(data: VaultAccess):
    conn = sqlite3.connect(config.DB_NAME)
    c = conn.cursor()
    
    c.execute("SELECT real_password, duress_tokens, wrapped_key FROM secure_containers WHERE vault_id=?", (data.vault_id,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        logger.error(f"Access attempt on non-existent container: {data.vault_id}")
        raise HTTPException(status_code=404, detail="Container not found or keys purged.")
    
    real_pwd, tokens_json, master_key = row
    
    try:
        duress_list = json.loads(tokens_json)
    except:
        duress_list = []

    # --- SECURITY CHECK PROTOCOL ---
    
    # SCENARIO 1: DURESS TOKEN DETECTED (Baskı Altında) 🚨
    if data.password in duress_list:
        logger.critical(f"SECURITY ALERT: Duress token used for container {data.vault_id}. INITIATING KEY PURGE.")
        
        # 1. DELETE KEY (Immediate Revocation)
        c.execute("DELETE FROM secure_containers WHERE vault_id=?", (data.vault_id,))
        conn.commit()
        conn.close()
        
        # 2. GENERATE DECOY KEY 
        decoy_key = secrets.token_bytes(32)
        
        return {
            "status": "success", 
            "key": decoy_key.hex(), 
            "mode": "emergency_revocation" # Client bunu görünce sessiz kalacak
        }

    # SCENARIO 2: AUTHORIZED ACCESS ✅
    elif data.password == real_pwd:
        conn.close()
        logger.info(f"Authorized access granted: {data.vault_id}")
        return {
            "status": "success", 
            "key": master_key.hex(), 
            "mode": "access_granted"
        }

    # SCENARIO 3: INVALID CREDENTIALS ❌
    else:
        conn.close()
        logger.warning(f"Failed authentication attempt: {data.vault_id}")
        raise HTTPException(status_code=401, detail="Authentication Failed: Invalid Credentials.")

if __name__ == "__main__":
    # Config'den port çekiyoruz (Varsayılan 8001)
    port = 8001
    try:
        # URL "http://127.0.0.1:8001" formatındaysa portu ayıkla
        port = int(config.KMS_SERVER_URL.split(":")[-1])
    except:
        pass
        
    print(f"[*] Oubliette Enterprise KMS running on port {port}...")

    uvicorn.run(app, host="127.0.0.1", port=port)
