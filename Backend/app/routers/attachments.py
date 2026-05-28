from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel, field_validator
from app.services import virustotal
from app.config import get_settings
from app.utils.logger import setup_logger

logger = setup_logger(__name__)
settings = get_settings()
router = APIRouter()

class HashCheckRequest(BaseModel):
    hash: str

    @field_validator('hash')
    @classmethod
    def validate_hash(cls, v: str) -> str:
        v = v.strip()
        # MD5 is 32 chars, SHA1 is 40 chars, SHA256 is 64 chars
        if len(v) not in (32, 40, 64):
            raise ValueError("Hash must be MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex)")
        return v

@router.post("/scan")
async def scan_attachment(file: UploadFile = File(...)):
    # Read file
    content = await file.read()
    
    # Check size
    size_mb = len(content) / (1024 * 1024)
    if size_mb > settings.MAX_ATTACHMENT_SIZE_MB:
        raise HTTPException(
            status_code=400, 
            detail=f"File too large ({size_mb:.1f}MB). Max allowed is {settings.MAX_ATTACHMENT_SIZE_MB}MB"
        )
        
    # Compute hashes
    md5, sha256 = virustotal.compute_file_hashes(content)
    
    # Check reputation via VT hash lookup
    logger.info(f"Scanning attachment {file.filename} (SHA256: {sha256})")
    vt_result = await virustotal.scan_file_hash(sha256)
    
    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "size_bytes": len(content),
        "md5": md5,
        "sha256": sha256,
        "scan_result": vt_result
    }

@router.post("/hash")
async def check_hash(request: HashCheckRequest):
    logger.info(f"Checking known hash: {request.hash}")
    vt_result = await virustotal.scan_file_hash(request.hash)
    return {
        "hash": request.hash,
        "scan_result": vt_result
    }
