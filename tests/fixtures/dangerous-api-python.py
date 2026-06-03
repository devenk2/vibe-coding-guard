# Intentionally vulnerable Python API file for testing Vibe Coding Guard
# DO NOT use this code in production

import requests
import jwt
import yaml
import json
import traceback
from fastapi import FastAPI, APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()
router = APIRouter()

# HIGH: CORS wildcard origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)

# HIGH: SSRF via f-string URL
@router.get("/proxy")
async def proxy_request(url: str):
    response = requests.get(f"https://api.example.com/{url}")
    return response.json()

# HIGH: SSRF via string concatenation
@router.get("/fetch")
async def fetch_data(endpoint: str):
    response = requests.get("https://api.example.com/" + endpoint)
    return response.json()

# HIGH: API key in URL query parameter
def call_external_api(data):
    url = "https://api.service.com/v1/data?api_key=sk_live_abc123def456"
    return requests.get(url)

# HIGH: JWT without verification
@router.get("/profile")
async def get_profile(token: str):
    payload = jwt.decode(token, options={"verify_signature": False}, verify=False)
    return payload

# HIGH: JWT algorithm none
def create_token(data):
    return jwt.encode(data, "", algorithm="none")

# MEDIUM: POST route without authentication dependency
@router.post("/items")
async def create_item(request: Request):
    body = await request.json()
    return {"status": "created"}

# MEDIUM: DELETE route without authentication
@router.delete("/items/{item_id}")
async def delete_item(item_id: int):
    return {"status": "deleted"}

# MEDIUM: No rate limiting on API routes (detected at app level)
# (The FastAPI() definition above has routes but no rate limit import)

# MEDIUM: No security headers middleware
# (The FastAPI() definition above has no security headers)

# MEDIUM: Sensitive data in API responses
@router.get("/user/{user_id}")
async def get_user(user_id: int):
    user = {"id": user_id, "name": "John", "password": "hashed_pw", "ssn": "123-45-6789"}
    return JSONResponse(content=json.dumps({"user": user, "password": user["password"]}))

# MEDIUM: Verbose error response with traceback
@router.get("/data")
async def get_data():
    try:
        result = do_something()
    except Exception as e:
        return JSONResponse(content={"error": str(e), "trace": traceback.format_exc()})

# MEDIUM: Open redirect
@router.get("/redirect")
async def handle_redirect(request: Request):
    next_url = request.query_params.get("next")
    return RedirectResponse(url=next_url)

# MEDIUM: Deserializing YAML from request body
@router.post("/config")
async def update_config(request: Request):
    body = await request.body()
    config = yaml.load(body, Loader=yaml.Loader)
    return config

# MEDIUM: Django-style fields = '__all__'
# class UserSerializer:
#     class Meta:
#         fields = '__all__'

# LOW: requests.get without timeout
def fetch_external():
    response = requests.get("https://api.example.com/data")
    return response.json()

# LOW: requests.post without timeout
def send_data(payload):
    response = requests.post("https://api.example.com/submit", json=payload)
    return response.status_code
