"""
We are doing here:
1. Basic email validation using a regex pattern.
2. DNS lookup for MX (or fallback to A) records to check if the email's domain can receive mail.
3. SMTP verification: connecting to the recipient's mail server to simulate sending an email,
   without actually delivering a message.
"""

import re
import dns.resolver
import smtplib
import socket
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

@dataclass
class EmailValidationResult:
    email: str
    is_valid: bool
    has_valid_format: bool
    has_mx_record: bool
    error_message: Optional[str] = None
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}

def is_valid_email(email):
    """
    Basic email validation using a regex pattern.
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def get_mx_record(domain):
    """
    Retrieve the mail server for the given domain.
    Tries to resolve MX records first.
    If MX lookup fails, attempts to resolve A records and returns its IP address.
    Returns the hostname or IP address of the mail server if found, otherwise None.
    """
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        # Sort by preference (lowest first) and extract the first record.
        mx_record = sorted(answers, key=lambda r: r.preference)[0].exchange.to_text().rstrip('.')
        return mx_record
    except Exception as e:
        print(f"DNS MX lookup failed for domain {domain}: {e}. Trying A record as fallback.")
        try:
            answers = dns.resolver.resolve(domain, 'A')
            # If successful, return the first A record.
            ip = answers[0].to_text()
            return ip
        except Exception as a_e:
            print(f"DNS A record lookup failed for domain {domain}: {a_e}")
            return None

def smtp_verify(email, sender_email="verify@example.com"):
    """
    Connect to the mail server via SMTP and simulate the SMTP conversation to verify the recipient.
    Returns True if the server responds with a code indicating that the mailbox exists.
    
    > Updated to force IPv4 resolution to avoid network unreachable errors on some environments.
    """
    domain = email.split('@')[1]
    mx_record = get_mx_record(domain)
    if not mx_record:
        # If we cannot get an MX record, there's no valid mail server.
        return False

    try:
        # Force IPv4 resolution: resolve the MX hostname to an IPv4 address.
        ip = socket.gethostbyname(mx_record)
        # Establish a connection to the mail server at port 25 with increased timeout.
        server = smtplib.SMTP(timeout=20)
        server.set_debuglevel(1)  # Enabled debug output.
        server.connect(ip, 25)
        server.ehlo()  # Introduce ourselves with EHLO.
        # Specify the sender (this can be any valid email address).
        server.mail(sender_email)
        # Ask the server if the recipient exists.
        code, message = server.rcpt(email)
        server.quit()
        # Codes 250 or 251 generally mean the mailbox exists.
        return code in (250, 251)
    except Exception as e:
        print(f"SMTP verification failed for {email}: {e}")
        return False

def verify_email_candidate(email: str) -> EmailValidationResult:
    """
    Verify if an email is potentially deliverable by checking:
    1. Its syntax (using a regex).
    2. DNS lookup for MX records.
    3. SMTP verification to check for mailbox existence.
    """
    details = {}
    
    # Step 1: Syntax validation
    has_valid_format = is_valid_email(email)
    if not has_valid_format:
        return EmailValidationResult(
            email=email,
            is_valid=False,
            has_valid_format=False,
            has_mx_record=False,
            error_message="Invalid email format",
            details={"format_check": "failed"}
        )

    # Step 2: DNS MX Record check
    domain = email.split('@')[1]
    mx_record = get_mx_record(domain)
    has_mx_record = mx_record is not None
    details["mx_record"] = mx_record

    if not has_mx_record:
        return EmailValidationResult(
            email=email,
            is_valid=False,
            has_valid_format=True,
            has_mx_record=False,
            error_message="No valid mail server found for domain",
            details=details
        )

    # Step 3: SMTP Verification
    smtp_valid = smtp_verify(email)
    details["smtp_check"] = "passed" if smtp_valid else "failed"

    return EmailValidationResult(
        email=email,
        is_valid=smtp_valid,
        has_valid_format=True,
        has_mx_record=True,
        error_message=None if smtp_valid else "SMTP verification failed",
        details=details
    )

# Example usage:
if __name__ == "__main__":
    test_email = "satyam21092@gmail.com"
    result = verify_email_candidate(test_email)
    if result.is_valid:
        print(f"{test_email} is potentially deliverable.")
    else:
        print(f"{test_email} is not deliverable: {result.error_message}")
