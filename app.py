from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
import hashlib
import requests
import zxcvbn
import secrets
import string
import os

# --- CONFIGURATION MULTI-CLIENTS ---
API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_authorized_keys():
    """
    Récupère la liste des clés depuis les variables d'environnement.
    Format attendu : "CLE_CLIENT_A,CLE_CLIENT_B,CLE_CLIENT_C"
    """
    # On récupère la chaîne de caractères, sinon une chaîne vide par défaut
    keys_raw = os.getenv("ALLOWED_API_KEYS", "")
    # On transforme la chaîne en liste en coupant au niveau des virgules
    return [k.strip() for k in keys_raw.split(",") if k.strip()]

async def verify_api_key(header_key: str = Depends(api_key_header)):
    authorized_keys = get_authorized_keys()
    
    if header_key in authorized_keys:
        return header_key
    
    raise HTTPException(
        status_code=403, 
        detail="Accès refusé : Clé API invalide, révoquée ou manquante."
    )

app = FastAPI(title="CyberBrain Multi-Client API")

# --- MOTEURS DE GÉNÉRATION (Inchangés pour la cohérence) ---
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

    suggestion = None
    if score <= 3:
        suggestion = {
            "passphrase_narrative": generer_hybride(lang),
            "random_code": ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        }

    return {
        "score": score,
        "pwned_leaks": leaks,
        "recommendation": suggestion,
        "client_authenticated": True
    }
