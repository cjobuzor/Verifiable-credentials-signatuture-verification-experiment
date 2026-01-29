import base64, json, subprocess, time, uuid, tempfile, os

# Base64url helper
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

# Generate an Ed25519 keypair in a directory
def generate_ed25519_keypair(directory: str):
    priv_path = os.path.join(directory, "priv.pem")
    pub_path  = os.path.join(directory, "pub.pem")
    subprocess.run(["openssl","genpkey","-algorithm","Ed25519","-out",priv_path], check=True)
    subprocess.run(["openssl","pkey","-in",priv_path,"-pubout","-out",pub_path], check=True)
    return priv_path, pub_path

# Sign a message using the private key
def ed25519_sign(priv_key_path: str, message: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(message); f.flush()
        msg_path = f.name
    sig_path = tempfile.mktemp()
    try:
        subprocess.run(["openssl","pkeyutl","-sign","-inkey",priv_key_path,
                        "-rawin","-in",msg_path,"-out",sig_path], check=True)
        with open(sig_path,"rb") as f:
            signature = f.read()
    finally:
        os.unlink(msg_path)
        if os.path.exists(sig_path):
            os.unlink(sig_path)
    return signature

# Verify a signature using the public key
def ed25519_verify(pub_key_path: str, message: bytes, signature: bytes) -> bool:
    with tempfile.NamedTemporaryFile(delete=False) as msg_file:
        msg_file.write(message); msg_file.flush(); msg_path = msg_file.name
    with tempfile.NamedTemporaryFile(delete=False) as sig_file:
        sig_file.write(signature); sig_file.flush(); sig_path = sig_file.name
    try:
        result = subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",pub_key_path,
                                 "-rawin","-in",msg_path,"-sigfile",sig_path])
        return result.returncode == 0
    finally:
        os.unlink(msg_path); os.unlink(sig_path)

# Create a JWS with Ed25519 signature
def create_jwt(payload: dict, priv_key_path: str) -> str:
    header = {"alg":"EdDSA","typ":"JWT"}
    h64 = b64url_encode(json.dumps(header, separators=(',',':')).encode('utf-8'))
    p64 = b64url_encode(json.dumps(payload, separators=(',',':')).encode('utf-8'))
    signing_input = f"{h64}.{p64}".encode('utf-8')
    signature = ed25519_sign(priv_key_path, signing_input)
    s64 = b64url_encode(signature)
    return f"{h64}.{p64}.{s64}"

# Verify a JWT and return its payload
def verify_jwt(token: str, pub_key_path: str) -> dict:
    h64,p64,s64 = token.split('.')
    signing_input = f"{h64}.{p64}".encode('utf-8')
    signature = base64.urlsafe_b64decode(s64 + '=' * (-len(s64) % 4))
    if not ed25519_verify(pub_key_path, signing_input, signature):
        raise ValueError("Invalid signature")
    payload_json = base64.urlsafe_b64decode(p64 + '=' * (-len(p64) % 4)).decode('utf-8')
    return json.loads(payload_json)

# Build a VC payload (template from the paper)
def create_vc_payload():
    return {
        "iss": "did:example:supplier123",
        "sub": "did:example:manufacturer456",
        "nbf": 1735689600,
        "exp": 1767225600,
        "jti": "urn:uuid:" + str(uuid.uuid4()),
        "typ": "vc+jwt",
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v2"],
            "type": ["VerifiableCredential","MaterialSupplyCredential"],
            "issuer": "did:example:supplier123",
            "credentialSubject": {
                "id": "did:example:manufacturer456",
                "materialType": "cotton",
                "quantity": {"value": 3, "unit": "Tonnes"},
                "batchId": "batch-123345",
                "supplyDate": "2025-01-17"
            },
            "credentialStatus": {
                "id": "https://status.example.org/status/123#45",
                "type": "StatusList2021Entry",
                "statusPurpose": "revocation",
                "statusListIndex": "45",
                "statusListCredential": "https://status.example.org/status/123"
            }
        }
    }

# Generate keys for issuer and holder
base_dir = tempfile.mkdtemp()
issuer_priv, issuer_pub = generate_ed25519_keypair(os.path.join(base_dir, 'issuer'))
holder_priv, holder_pub = generate_ed25519_keypair(os.path.join(base_dir, 'holder'))

# Measure verification time for a single VC
single_vc = create_jwt(create_vc_payload(), issuer_priv)
start = time.perf_counter()
verify_jwt(single_vc, issuer_pub)
single_vc_verify_time_ms = (time.perf_counter() - start)*1000

# Measure VP verification time for multiple aggregated VCs
for N in [5,10,20,40,80]:
    vc_jwts = [create_jwt(create_vc_payload(), issuer_priv) for _ in range(N)]
    vp_payload = {
        "iss": "did:example:holder789",
        "nbf": 1735689600,
        "exp": 1767225600,
        "jti": "urn:uuid:" + str(uuid.uuid4()),
        "typ": "vp+jwt",
        "vp": {
            "@context": ["https://www.w3.org/2018/credentials/v2"],
            "type": ["VerifiablePresentation","MaterialSupplyPresentation"],
            "verifiableCredential": vc_jwts
        }
    }
    vp_jwt = create_jwt(vp_payload, holder_priv)
    t0 = time.perf_counter()
    verify_jwt(vp_jwt, holder_pub)
    vp_verify_time_ms = (time.perf_counter() - t0)*1000
    print(f"N = {N}: VP verify time = {vp_verify_time_ms:.3f} ms; Single VC verify time = {single_vc_verify_time_ms:.3f} ms")
