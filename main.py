from fastapi import FastAPI, HTTPException, Security, Depends, Request
from fastapi.security.api_key import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import secrets
import hashlib
import requests
import zxcvbn
import os
import string

# Configuration Sécurité
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="CyberBrain API Secure Pro")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_authorized_keys():
    keys_raw = os.getenv("ALLOWED_API_KEYS", "")
    return [k.strip() for k in keys_raw.split(",") if k.strip()]

async def verify_api_key(header_key: str = Depends(api_key_header)):
    authorized_keys = get_authorized_keys()
    is_valid = any(secrets.compare_digest(header_key or "", k) for k in authorized_keys)
    if is_valid: return header_key
    raise HTTPException(status_code=403, detail="Clé API invalide ou manquante")

# --- MOTEURS DE GÉNÉRATION ---
def get_diceware_word(langue="Français"):
    nom_fichier = "diceware-fr.txt" if langue == "Français" else "diceware-en.txt"
    if os.path.exists(nom_fichier):
        with open(nom_fichier, "r", encoding="utf-8") as f:
            dictionnaire = [l.split()[1] for l in f.readlines() if len(l.split()) > 1]
            return secrets.choice(dictionnaire)
    return "cyber"

def generer_hybride(langue="Français"):
    mots = [get_diceware_word(langue).capitalize() if secrets.choice([True, False]) else get_diceware_word(langue) for _ in range(4)]
    separateurs = [".", ",", ";", ":", "!", "?", "£", "$"]
    phrase = "".join([m + (secrets.choice(separateurs) if i < 3 else "") for i, m in enumerate(mots)])
    return phrase + secrets.choice(string.digits)

# --- ROUTE 1 : AUDIT MOT DE PASSE ---
@app.get("/audit")
@limiter.limit("5/minute")
def audit_password(request: Request, pwd: str, lang: str = "Français", token: str = Depends(verify_api_key)):
    if len(pwd) > 128:
        raise HTTPException(status_code=400, detail="Mot de passe trop long (max 128 car.)")

    analysis = zxcvbn.zxcvbn(pwd)
    score = analysis['score']
    
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

    # Génération d'un token hautement diversifié (lettres, chiffres, symboles)
    # On crée un alphabet robuste pour exclure toute prédictibilité
    alphabet_secu = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    mot_de_passe_aleatoire = "".join(secrets.choice(alphabet_secu) for _ in range(16))

    return {
        "status": "secure" if score > 3 and leaks == 0 else "warning",
        "score": score,
        "pwned_leaks": leaks,
        "recommendation": {
            "passphrase_suggestion": generer_hybride(lang),
            "random_token": mot_de_passe_aleatoire  # <-- Ce jeton contient désormais de vrais caractères diversifiés
        }
    }

# --- ROUTE CORRIGÉE : AUDIT EMAIL AVEC GESTION DU 404 ---
@app.get("/audit-email")
@limiter.limit("5/minute")
def audit_email(request: Request, email: str, token: str = Depends(verify_api_key)):
    if "@" not in email or "." not in email:
        raise HTTPException(status_code=400, detail="Format d'email invalide.")

    url = f"https://api.proxynova.com/v1/breach?email={email}"
    
    try:
        res = requests.get(url, timeout=5)
        
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "breached":
                breaches = data.get("results", [])
                return {
                    "status": "danger",
                    "email": email,
                    "breach_count": len(breaches),
                    "details": breaches,
                    "message": f"Cet email apparaît dans {len(breaches)} fuites de données."
                }
            else:
                return {
                    "status": "clean",
                    "email": email,
                    "breach_count": 0,
                    "details": [],
                    "message": "Aucune fuite détectée pour cet email."
                }
                
        # --- AJOUT DE LA LOGIQUE PROXYNOVA : 404 SIGNIFIE SANS DANGER ---
        elif res.status_code == 404:
            return {
                "status": "clean",
                "email": email,
                "breach_count": 0,
                "details": [],
                "message": "Aucune fuite détectée pour cet email (0 breach)."
            }
            
        else:
            return {"status": "error", "message": f"Le scanner alternatif a répondu avec le code {res.status_code}."}
            
    except Exception as e:
        return {"status": "error", "message": f"Erreur de connexion au scanner : {str(e)}"}
        # LIGNE 118 CORRIGÉE ICI :
        return {"status": "error", "message": f"Erreur de connexion au scanner : {str(e)}"}
