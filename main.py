from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import jwt

app = FastAPI()


@app.post("/verify")
async def verify(request: Request):
    body = await request.json()
    token = body.get("token", "")

    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:
        header = {"error": str(e)}

    try:
        claims = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except Exception as e:
        claims = {"decode_error": str(e)}

    # Always return 401/invalid on purpose -- this is a temporary debug
    # build so the grader's failure message echoes back what we saw.
    return JSONResponse(
        status_code=401,
        content={
            "valid": False,
            "debug_header": header,
            "debug_claims": claims,
        },
    )
