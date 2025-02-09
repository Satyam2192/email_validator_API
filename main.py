from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from validate_email import verify_email_candidate
import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


PORT = int(os.environ.get("PORT", 10000))

# Initialize FastAPI app with additional configuration
app = FastAPI(
    title="Email Validation API",
    description="API for validating email addresses",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

class EmailRequest(BaseModel):
    email: EmailStr

class EmailResponse(BaseModel):
    email: str
    is_valid: bool
    has_valid_format: bool
    has_mx_record: bool
    error_message: Optional[str] = None
    details: Dict[str, Any]

@app.post("/validate_email", response_model=EmailResponse)
@limiter.limit("100/minute")  # Rate limit: 100 requests per minute per IP
async def validate_email_endpoint(request: Request, email_req: EmailRequest):
    """
    Validate an email address by checking its format and DNS records.
    
    Args:
        email_req: EmailRequest object containing the email to validate
        
    Returns:
        JSONResponse with validation results
        
    Raises:
        HTTPException: If the request is malformed or rate limited
    """
    try:
        result = verify_email_candidate(email_req.email)
        
        return EmailResponse(
            email=result.email,
            is_valid=result.is_valid,
            has_valid_format=result.has_valid_format,
            has_mx_record=result.has_mx_record,
            error_message=result.error_message,
            details=result.details
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.on_event("startup")
async def startup_event():
    """Startup event handler"""
    logger.info("Starting up Email Validation API")
    logger.info(f"Server running on port {PORT}")

@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event handler"""
    logger.info("Shutting down Email Validation API")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        reload=False,
        workers=4
    ) 