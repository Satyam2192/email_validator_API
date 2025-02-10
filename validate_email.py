import re
import dns.resolver
import smtplib
import socket  # <-- For IPv4 resolution

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
            ip = answers[0].to_text()
            return ip
        except Exception as a_e:
            print(f"DNS A record lookup failed for domain {domain}: {a_e}")
            return None

def smtp_verify(email, sender_email="verify@example.com"):
    """
    Connect to the mail server via SMTP and simulate the SMTP conversation to verify the recipient.
    Returns True if the server responds with a code indicating that the mailbox exists.
    
    Note: Some mail servers (like Gmail) may not provide definitive responses due to anti-spam measures.
    """
    domain = email.split('@')[1]
    mx_record = get_mx_record(domain)
    if not mx_record:
        # No valid mail server found.
        return False

    try:
        # Force IPv4 resolution by resolving the MX hostname.
        ip = socket.gethostbyname(mx_record)
        # Establish a connection to the mail server at port 25.
        server = smtplib.SMTP(timeout=10)
        # Uncomment the following line for verbose SMTP debug output:
        # server.set_debuglevel(1)
        server.connect(ip, 25)
        server.helo(server.local_hostname)  # Introduce ourselves.
        server.mail(sender_email)
        # Ask the server if the recipient exists.
        code, message = server.rcpt(email)
        server.quit()
        # SMTP codes 250 or 251 typically indicate that the mailbox exists.
        return code in (250, 251)
    except Exception as e:
        print(f"SMTP verification failed for {email}: {e}")
        return False

def verify_email_candidate(email):
    """
    Verify if an email address is potentially deliverable.
    Checks include: syntax, MX record existence, and SMTP verification.
    Returns a dictionary with the keys:
    - email: the provided email address.
    - is_valid: overall validation result.
    - has_valid_format: result of regex validation.
    - has_mx_record: whether an MX record was found.
    - error_message: error message if validation failed.
    - details: additional details for the validation process.
    """
    details = {}
    has_valid_format = is_valid_email(email)
    details["has_valid_format"] = has_valid_format
    if not has_valid_format:
        error_message = "Invalid email syntax."
        details["error"] = error_message
        return {
            "email": email,
            "is_valid": False,
            "has_valid_format": False,
            "has_mx_record": False,
            "error_message": error_message,
            "details": details
        }
    # Retrieve MX record for the domain.
    domain = email.split('@')[1]
    mx_record = get_mx_record(domain)
    has_mx_record = mx_record is not None
    details["mx_record"] = mx_record
    details["has_mx_record"] = has_mx_record
    if not has_mx_record:
        error_message = "No MX record found for the email domain."
        details["error"] = error_message
        return {
            "email": email,
            "is_valid": False,
            "has_valid_format": True,
            "has_mx_record": False,
            "error_message": error_message,
            "details": details
        }
    # Perform SMTP verification.
    smtp_valid = smtp_verify(email)
    details["smtp_valid"] = smtp_valid
    if smtp_valid:
        print("SMTP verification succeeded.")
    else:
        print("SMTP verification failed.")
    is_valid = has_valid_format and has_mx_record and smtp_valid
    error_message = None if is_valid else "SMTP verification failed."
    return {
        "email": email,
        "is_valid": is_valid,
        "has_valid_format": has_valid_format,
        "has_mx_record": has_mx_record,
        "error_message": error_message,
        "details": details
    }

# Example usage:
if __name__ == "__main__":
    test_email = "satysdfdam2wd1029@gmail.com"
    if verify_email_candidate(test_email):
        print(f"{test_email} is potentially deliverable.")
    else:
        print(f"{test_email} is not deliverable.")
