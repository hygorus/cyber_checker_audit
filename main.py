from fastapi import FastAPI, HTTPException, Security, Depends, Request
from fastapi.security.api_key import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import secrets
import hashlib
import requests
import zxcvbn
import string
import os

# --- 1 & 2. CONFIGURATION RATE LIMIT & MASQUAGE ---
# On limite à 5 requêtes par minute pour protéger l'instance gratuite
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="CyberBrain API Secure Pro",
    docs_url="/docs", 
    redoc_url=None,
    # Masquage partiel via les paramètres de l'application
    openapi_url="/api/v1/openapi.json" 
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_authorized_keys():
    keys_raw = os.getenv("ALLOWED_API_KEYS", "")
    return [k.strip() for k in keys_raw.split(",") if k.strip()]

# --- 4. COMPARAISON EN TEMPS CONSTANT ---
async def verify_api_key(header_key: str = Depends(api_key_header)):
    authorized_keys = get_authorized_keys()
    
    # On utilise secrets.compare_digest pour éviter les Timing Attacks
    is_valid = any(secrets.compare_digest(header_key or "", k) for k in authorized_keys)
    
    if is_valid:
        return header_key
    
    raise HTTPException(status_code=403, detail="Accès refusé.")

# --- MOTEURS DE GÉNÉRATION (Inchangés) ---
def get_diceware_word(langue="Français"):
    nom_fichier = "diceware-fr.txt" if langue == "Français" else "diceware-en.txt"
    if os.path.exists(nom_fichier):
        with open(nom_fichier, "r", encoding="utf-8") as f:
            dictionnaire = [l.split()[1] for l in f.readlines() if len(l.split()) > 1]
            return secrets.choice(dictionnaire)
    return "cyber"

# --- 3. AUDIT AVEC LIMITATION DE TAILLE ---
@app.get("/audit")
@limiter.limit("5/minute") # Limitation de débit
def audit_password(
    request: Request, 
    pwd: str, 
    lang: str = "Français", 
    token: str = Depends(verify_api_key)
):
    # Sécurité : Limitation de la taille pour éviter les DoS
    if len(pwd) > 128:
        raise HTTPException(status_code=400, detail="Mot de passe trop long (max 128 car.)")

    analysis = zxcvbn.zxcvbn(pwd)
    score = analysis['score']
    
    # Audit HIBP
    sha1 = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    leaks = 0
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if res.status_code == 200:
            for line in res.text.splitlines():
                h, count = line.split(':')
                if h == suffix: leaks = int(count)
    except: pass

    return {
        "score": score,
        "pwned_leaks": leaks,
        "status": "secure" if score > 3 and leaks == 0 else "warning"
    }
