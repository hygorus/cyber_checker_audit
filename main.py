from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
import hashlib
import requests
import zxcvbn
import secrets
import string
import os

# --- CONFIGURATION DE SÉCURITÉ ---
# C'est ici que tu définis ta clé secrète. 
# En production, on utilise normalement des variables d'environnement.
API_KEY = "CYBER-YVES-2026-SECRET-KEY" 
API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

app = FastAPI(title="CyberBrain API Secure")

# Fonction de vérification de la clé
async def verify_api_key(header_key: str = Depends(api_key_header)):
    # On récupère la valeur brute de Render
    raw_keys = os.getenv("ALLOWED_API_KEYS", "NON_DEFINIE")
    authorized_keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
    
    # Ce message nous dira exactement ce que le serveur "voit"
    if header_key not in authorized_keys:
        raise HTTPException(
            status_code=403, 
            detail=f"Refusé. Reçu: '{header_key}'. Liste détectée: {authorized_keys}"
        )
    return header_key

# --- MOTEURS DE GÉNÉRATION (Inchangés) ---
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

# --- POINT D'ENTRÉE SÉCURISÉ ---

@app.get("/audit")
def audit_password(pwd: str, lang: str = "Français", token: str = Depends(verify_api_key)):
    """
    Cette fonction nécessite désormais un token valide pour répondre.
    """
    analysis = zxcvbn.zxcvbn(pwd)
    score = analysis['score']
    
    # Audit HIBP
    sha1 = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    leaks = 0
    res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    if res.status_code == 200:
        for line in res.text.splitlines():
            h, count = line.split(':')
            if h == suffix: leaks = int(count)

    suggestion = None
    if score <= 3:
        suggestion = {
            "passphrase_narrative": generer_hybride(lang),
            "random_code": ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        }

    return {
        "status": "secure" if score > 3 and leaks == 0 else "warning",
        "score": score,
        "pwned_leaks": leaks,
        "recommendation": suggestion
    }
