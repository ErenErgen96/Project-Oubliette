import os
import sys
import errno
import logging
import argparse
import string
from time import time
from stat import S_IFDIR, S_IFREG
from fuse import FUSE, FuseOSError, Operations

# Configuration Import
try:
    import config
except ImportError:
    # Fallback for standalone testing
    class Config:
        CONTAINER_SIZE_MB = 100
    config = Config()

# Import Storage Backend
try:
    from storage_manager import VaultStorage
except ImportError:
    print("[CRITICAL] 'storage_manager.py' not found. System integrity compromised.")
    sys.exit(1)

# Logging Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - FUSE - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EncryptedFS(Operations):
    """
    Enterprise-grade FUSE implementation for Oubliette.
    Bridges OS file operations to AES-256-XTS Encrypted Storage.
    """
    
    def __init__(self, storage_backend):
        self.storage = storage_backend
        self.fd = 0
        self.now = time()

    # =========================================
    # SYSTEM COMPATIBILITY STUBS
    # =========================================
    
    def getxattr(self, path, name, position=0):
        return b''

    def listxattr(self, path):
        return []

    # =========================================
    # METADATA OPERATIONS
    # =========================================

    def getattr(self, path, fh=None):
        """Retrieves file attributes."""
        # 1. Root Directory
        if path == '/':
            return dict(st_mode=(S_IFDIR | 0o755), st_nlink=2, 
                        st_ctime=self.now, st_mtime=self.now, st_atime=self.now)
        
        filename = path[1:] # Strip leading slash
        
        # 2. File Check
        if filename in self.storage.file_map:
            meta = self.storage.file_map[filename]
            return dict(st_mode=(S_IFREG | 0o644), st_nlink=1, st_size=meta['size'], 
                        st_ctime=self.now, st_mtime=self.now, st_atime=self.now)

        # 3. Virtual Directory Logic
        is_dir = any(key.startswith(filename + "/") for key in self.storage.file_map.keys())
        
        if is_dir:
             return dict(st_mode=(S_IFDIR | 0o755), st_nlink=2, 
                         st_ctime=self.now, st_mtime=self.now, st_atime=self.now)

        raise FuseOSError(errno.ENOENT)

    def statfs(self, path):
        """
        Reports disk usage statistics based on Config.
        """
        # USE CONFIGURATION FOR SIZE
        TOTAL_SPACE = config.CONTAINER_SIZE_MB * 1024 * 1024
        BLOCK_SIZE = 512
        
        used_blocks = self.storage.next_free_sector
        total_blocks = TOTAL_SPACE // BLOCK_SIZE
        free_blocks = max(0, total_blocks - used_blocks)
        
        return dict(f_bsize=BLOCK_SIZE, f_blocks=total_blocks, f_bfree=free_blocks, f_bavail=free_blocks)

    def readdir(self, path, fh):
        """Lists files and directory contents."""
        listing = ['.', '..']
        prefix = "" if path == "/" else path[1:] + "/"
        seen_folders = set()
        
        for filename in self.storage.file_map.keys():
            if filename.startswith(prefix):
                relative_path = filename[len(prefix):]
                
                # Filter hidden system markers
                if relative_path == ".marker":
                    continue

                if "/" in relative_path:
                    folder_name = relative_path.split("/")[0]
                    if folder_name not in seen_folders:
                        listing.append(folder_name)
                        seen_folders.add(folder_name)
                elif relative_path:
                    listing.append(relative_path)
                    
        return listing

    # =========================================
    # FILE OPERATIONS (READ / WRITE)
    # =========================================

    def read(self, path, size, offset, fh):
        filename = path[1:]
        full_data = self.storage.read_file(filename)
        if full_data:
            return full_data[offset:offset + size]
        return b""

    def create(self, path, mode, fi=None):
        filename = path[1:]
        self.storage.write_file(filename, b"")
        self.fd += 1
        return self.fd

    def write(self, path, buf, offset, fh):
        filename = path[1:]
        current_data = self.storage.read_file(filename) or b""
        
        if offset == 0:
            new_data = buf + current_data[len(buf):]
        else:
            new_data = current_data[:offset] + buf + current_data[offset+len(buf):]
             
        self.storage.write_file(filename, new_data)
        return len(buf)
        
    def truncate(self, path, length, fh=None):
        filename = path[1:]
        current_data = self.storage.read_file(filename) or b""
        if len(current_data) != length:
            self.storage.write_file(filename, current_data[:length])

    def unlink(self, path):
        filename = path[1:]
        self.storage.delete_file(filename)

    # =========================================
    # DIRECTORY OPERATIONS
    # =========================================

    def mkdir(self, path, mode):
        folder_name = path[1:]
        marker_path = f"{folder_name}/.marker"
        self.storage.write_file(marker_path, b"")
        return 0

    def rmdir(self, path):
        folder_name = path[1:]
        keys_to_delete = []
        for key in self.storage.file_map.keys():
            if key.startswith(folder_name + "/"):
                keys_to_delete.append(key)
        
        for key in keys_to_delete:
            self.storage.delete_file(key)
        return 0

    def rename(self, old, new):
        old_name = old[1:]
        new_name = new[1:]
        
        data = self.storage.read_file(old_name)
        if data is not None:
            self.storage.write_file(new_name, data)
            self.storage.delete_file(old_name)
            return 0
        
        keys = list(self.storage.file_map.keys())
        found_any = False
        
        for key in keys:
            if key.startswith(old_name + "/"):
                found_any = True
                suffix = key[len(old_name):] 
                new_key = new_name + suffix
                file_data = self.storage.read_file(key)
                self.storage.write_file(new_key, file_data)
                self.storage.delete_file(key)
        
        if not found_any:
            raise FuseOSError(errno.ENOENT)
        return 0

# =========================================
# MOUNT POINT UTILITIES
# =========================================

def get_all_drives():
    import ctypes
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in string.ascii_uppercase:
        if bitmask & 1:
            drives.append(letter + ':')
        bitmask >>= 1
    return drives

def is_drive_available(drive_letter):
    if len(drive_letter) != 2 or drive_letter[1] != ':':
        return False
    
    existing_drives = get_all_drives()
    if drive_letter.upper() not in [d.upper() for d in existing_drives]:
        return True
    
    drive_path = drive_letter + '\\'
    try:
        os.listdir(drive_path)
        return False
    except (PermissionError, OSError, FileNotFoundError):
        return False
    except Exception:
        return False

# =========================================
# ENTRY POINT
# =========================================

def start_fuse(container_path, mount_point, password):
    """
    Initializes the FUSE system.
    Strict Mode: Does NOT switch drive letters automatically to ensure GUI sync.
    """
    
    # Clean up mount point format
    clean_mount_point = mount_point.rstrip("/\\")
    is_drive_letter = len(clean_mount_point) == 2 and clean_mount_point[1] == ':'
    
    if is_drive_letter:
        logger.info(f"Requested Mount Point: {clean_mount_point}")
        
        # STRICT CHECK: If drive is busy, FAIL immediately.
        # This allows the GUI to catch the error and lets the user choose another drive.
        if not is_drive_available(clean_mount_point):
            error_msg = f"Mount point {clean_mount_point} is currently IN USE. Please select a different drive letter."
            logger.error(error_msg)
            raise RuntimeError(f"Mount Error: {error_msg}")
        
        mount_point = clean_mount_point 
    else:
        if not os.path.exists(mount_point):
            try:
                os.makedirs(mount_point)
            except Exception as e:
                raise RuntimeError(f"Failed to create directory {mount_point}: {e}")

    logger.info(f"Initializing Encryption Engine for: {container_path}")
    
    try:
        # Initialize Vault (Connects to KMS via storage_manager)
        vault = VaultStorage(container_path, password)
        logger.info("Authentication Successful. Mounting File System...")
        
        # Start FUSE (Blocking Operation)
        FUSE(EncryptedFS(vault), mount_point, foreground=True, nothreads=False, allow_other=True, uid=-1, gid=-1)
        
    except RuntimeError as e:
        logger.error(f"Runtime Error: {e}")
        raise e
    except Exception as e:
        logger.error(f"Fatal FUSE Error: {e}")
        raise e

if __name__ == '__main__':
    print("[*] This module is part of the Oubliette Suite. Please run 'gui.py' instead.")