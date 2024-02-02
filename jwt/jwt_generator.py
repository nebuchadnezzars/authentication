import hashlib  # Import hashlib for hashing functionality
import hmac  # Import hmac for keyed-hashing functionality
import base64  # Import base64 for encoding/decoding functionality
import json  # Import json for JSON serialization/deserialization
import time  # Import time to handle expiration time


def create_jwt(username, permission):
    # Define JWT header specifying algorithm and token type
    header = {"alg": "HS256", "typ": "JWT"}

    # Define WT payload with username, permission and expiration time
    payload = {
        "username": username,
        "permission": permission,
        "exp": int(time.time()) + 3600,  # Expires in 1 hour
    }

    # Convert header and payload dictionaries to JSON strings
    header_json = json.dumps(header, separators=(",", ":"))
    payload_json = json.dumps(payload, separators=(",", ":"))

    # Encode header and payload JSON strings to base64url encoding
    header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
    # Create the signature using HMAC-SHA256 algorithm with the secret key
    # Use .digest() instead of •hexdigest() to get binary signature

    signature = hmac.new(
        b"thisismysecret",  # Secret key (replace with your actual secret key)
        f"{header_b64}.{payload_b64}".encode(),  # Concatenated base64url encoded header and payload
        hashlib.sha256,  # SHA-256 hashing algorithm
    ).digest()

    # Encode the binary signature to base64url encoding
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    # Concatenate header, payload and signature with dots to form the JWT
    jwt = f"{header_b64}.{payload_b64}.{signature_b64}"

    return jwt  # return the generated JWT


print(create_jwt("nuri.yavuz", "read"))
