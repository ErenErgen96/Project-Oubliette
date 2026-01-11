import os

"""
Oubliette DLP Solution - Configuration Manifest
-----------------------------------------------
Centralized configuration management for Client and Server components.
"""

# ==========================================
# 1. NETWORK & CONNECTIVITY
# ==========================================
# Development Environment: Localhost
KMS_SERVER_URL = os.getenv("OUBLIETTE_KMS_URL", "http://127.0.0.1:8001")

# Connection Timouts (Seconds)
CONNECTION_TIMEOUT = 5
READ_TIMEOUT = 10

# ==========================================
# 2. CRYPTOGRAPHIC STANDARDS
# ==========================================
# IEEE 1619 Standard for Storage Encryption
ENCRYPTION_ALGORITHM = "AES-256-XTS"

# Sector size mapping (Must match CryptoEngine specs)
SECTOR_SIZE = 512

# ==========================================
# 3. STORAGE & DATABASE ARCHITECTURE
# ==========================================
# Reserved header space for Metadata/Allocation Table
HEADER_SECTORS = 100

# Default Container Size (Can be dynamic in future)
CONTAINER_SIZE_MB = 100

# --- İŞTE EKSİK OLAN SATIR BU! ---
DB_NAME = "secure_keystore.sqlite"

# ==========================================
# 4. APPLICATION METADATA
# ==========================================
APP_NAME = "Oubliette Zero-Trust Endpoint"
VERSION = "3.2.0-Enterprise"
BUILD_LABEL = "DLP-2026-REL"