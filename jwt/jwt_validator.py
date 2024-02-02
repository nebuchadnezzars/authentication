import hashlib  # Import hashlib for hashing functionality
import hmac  # Import hmac for keyed-hashing functionality
import base64  # Import base64 for encoding/decoding functionality
import json  # Import json for JSON serialization/deserialization
import time  # Import time to handle expiration time


def verify_jwt(jwt):
    # Split the JWT into header, payload and signature parts
    header_b64, payload_b64, signature_b64 = jwt.split(".")

    # Decode base64url encoded header and payload back to JSON strings
    header_json = base64.urlsafe_b64decode(header_b64 + "==").decode()
    payload_json = base64.urlsafe_b64decode(payload_b64 + "==").decode()

    # Deserialize JSON strings to dictionaries
    header = json.loads(header_json)
    payload = json.loads(payload_json)

    # Re-calculate the signature using the same HMAC-SHA256 algorithm with the secret key
    # Use .digest() instead of•hexdigest() to get binary signature
    expected_signature = hmac.new(
        b"thisismysecret",  # Secret key (replace with your actual secret key)
        f"{header_b64}.{payload_b64}".encode(),  # Concatenated base64url encoded header and payload
        hashlib.sha256,  # SHA-256 hashing algorithm
    ).digest()

    # Encode the binary signature to base64url encoding
    expected_signature_b64 = (
        base64.urlsafe_b64encode(expected_signature).decode().rstrip("=")
    )

    # Compare the calculated signature with the provided signature to verify authenticity
    if expected_signature_b64 != signature_b64:
        return "Error: Invalid token"  # Return error message if signatures don't match

    if int(time.time()) > payload["exp"]:
        return "Error: Token has expired"

    username = payload["username"]
    permission = payload["permission"]

    # IF verification passed, return authorization message
    return f"Access granted to {username} with {permission}"


# Verify JWT
authorization = verify_jwt(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im51cmkueWF2dXoiLCJwZXJtaXNzaW9uIjoicmVhZCIsImV4cCI6MTcwNjg4NzYxMn0.jTK5hjfPiv0fnkUHL2bajhd3cjIZ0a5SfkfCTPue0f8"
)
print(authorization)
