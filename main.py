import os
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# ---- FILL THESE IN FROM YOUR PANEL ----
PUBLIC_KEY = os.environ.get("IDP_PUBLIC_KEY", """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----""")

EXPECTED_ISSUER = "https://idp.exam.local"
EXPECTED_AUDIENCE = os.environ.get("IDP_AUDIENCE", "tds-vtnswj30.apps.exam.local")
# ----------------------------------------


@app.post("/verify")
async def verify(request: Request):
    body = await request.json()
    token = body.get("token", "")

    try:
        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=EXPECTED_AUDIENCE,
            issuer=EXPECTED_ISSUER,
            options={"require": ["exp", "iss", "aud"]},
        )
    except jwt.PyJWTError as e:
        return JSONResponse(status_code=401, content={"valid": False, "debug_error": str(e), "debug_type": type(e).__name__})

    return {
        "valid": True,
        "email": claims.get("email"),
        "sub": claims.get("sub"),
        "aud": claims.get("aud"),
    }
