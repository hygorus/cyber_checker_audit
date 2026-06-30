from fastapi import FastAPI, HTTPException, Security, Depends, Request, Header, status
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import secrets
import hashlib
import requests
import zxcvbn
import os
import string
import logging
import jwt
from pydantic import BaseModel, Field, EmailStr
from database import get_db_connection, init_db
from crypto_utils import chiffrer_mot_de_passe, dechiffrer_mot_de_passe
from auth_utils import hacher_mot_de_passe_maitre, verifier_mot_de_passe_maitre
from datetime import datetime, timedelta, timezone


# ==========================================
# 0. CONFIGURATION DU JETON NUMERIQUE (JWT)
# ==========================================
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "UNE-CLE-SUPER-SECRETE-A-CHANGER")
JWT_ALGORITHM = "HS256"


# ==========================================
# 🔒 SÉCURITÉ ET DÉPENDANCES (JWT)
# ==========================================
def verifier_jeton_session(authorization: str = Header(None)):
    """Vérifie le jeton JWT fourni dans les en-têtes HTTP"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Session absente ou format invalide (Bearer requis).")
        
    token = authorization.split(" ")[1]
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["user_email"] 
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Votre session a expiré. Veuillez vous reconnecter.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Session invalide ou corrompue.")


# ==========================================
# 1. CONFIGURATION DU MONITORING (LOGS)
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("uvicorn.error")


# ==========================================
# 2. CONFIGURATION DU RATE LIMITER (SLOWAPI)
# ==========================================
def get_real_user_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        real_ip = forwarded_for.split(",")[0].strip()
        return real_ip
    return request.client.host if request.client else "127.0.0.1"

limiter = Limiter(key_func=get_real_user_ip)


# ==========================================
# 3. CONFIGURATION API ET MIDDLEWARES
# ==========================================
app = FastAPI(title="CyberBrain API Secure Pro", debug=False)

# 🌐 AJOUT : Configuration du CORS pour la liaison Frontend <-> Backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En production, remplacez par l'URL exacte de votre frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"🚨 ERREUR INTERNE NON GÉRÉE sur {request.url.path} : {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "Une erreur interne est survenue. L'incident a été enregistré par nos services de sécurité."
        }
    )

# Déclenche la création des tables sur PostgreSQL (Supabase)
init_db()

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# 🔒 BLINDAGE DE SÉCURITÉ
API_KEY = os.getenv("CLE_API_INTERNE")
if not API_KEY:
    raise RuntimeError("🚨 ERREUR CRITIQUE : La variable d'environnement 'CLE_API_INTERNE' est introuvable. Arrêt de sécurité.")

API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_authorized_keys():
    keys_raw = os.getenv("ALLOWED_API_KEYS", API_KEY)
    return [k.strip() for k in keys_raw.split(",") if k.strip()]

async def verify_api_key(header_key: str = Depends(api_key_header)):
    if header_key and secrets.compare_digest(header_key, API_KEY):
        masquage_cle = f"{header_key[:4]}****"
        logger.info(f"🔑 ACCÈS ACCORDÉ : La clé [{masquage_cle}] a validé une requête.")
        return header_key
        
    logger.warning("🚨 TENTATIVE D'INTRUSION : Une clé invalide ou manquante a été soumise.")
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


# ==========================================
# 5. MODÈLES DE DONNÉES (PYDANTIC)
# ==========================================
class ItemCoffre(BaseModel):
    nom_site: str
    url_site: str
    identifiant: str
    mot_de_passe_a_stocker: str

class UserAuth(BaseModel):
    email: EmailStr  
    password: str = Field(..., min_length=8, max_length=64)

class PasswordCheckInput(BaseModel):
    pwd: str = Field(..., min_length=1, max_length=128)
    lang: str = "Français"

# 🧠 AJOUT : Modèle propre pour l'audit email
class EmailCheckInput(BaseModel):
    email: EmailStr


# ==========================================
# 6. FONCTION INTERNE : AUDIT TEMPS RÉEL (HIBP)
# ==========================================
def verifier_fuite_mot_de_passe(mdp_clair: str) -> str:
    try:
        if not mdp_clair or mdp_clair == "[Erreur de déchiffrement]":
            return "❌ Impossible d'auditer"
            
        sha1_hash = hashlib.sha1(mdp_clair.encode('utf-8')).hexdigest().upper()
        prefixe = sha1_hash[:5]
        suffixe = sha1_hash[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefixe}"
        response = requests.get(url, timeout=4)
        
        if response.status_code == 200:
            lignes = response.text.splitlines()
            for ligne in lignes:
                hachage_recupere, nb_fuites = ligne.split(':')
                if hachage_recupere == suffixe:
                    return f"⚠️ Compromis (vu {nb_fuites} fois !)"
            return "✅ Sûr (aucune fuite détectée)"
        return "⚡ Audit indisponible (Serveur distant)"
    except Exception:
        return "🔍 Non audité (Timeout API)"


# ==========================================
# 7. ROUTES DE L'APPLICATION
# ==========================================

@app.post("/audit")
@limiter.limit("5/minute")
async def audit_password(request: Request, input_data: PasswordCheckInput, token: str = Depends(verify_api_key)):
    real_ip = get_real_user_ip(request)
    logger.info(f"🔐 LOG: Une analyse de mot de passe a été demandée depuis l'IP : {real_ip}")

    pwd = input_data.pwd
    lang = input_data.lang

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
                if h == suffix: 
                    leaks = int(count)
    except Exception: 
        pass

    alphabet_secu = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    mot_de_passe_aleatoire = "".join(secrets.choice(alphabet_secu) for _ in range(16))

    return {
        "status": "secure" if score > 3 and leaks == 0 else "warning",
        "score": score,
        "pwned_leaks": leaks,
        "recommendation": {
            "passphrase_suggestion": generer_hybride(lang),
            "random_token": mot_de_passe_aleatoire
        }
    }


# 🔄 CORRECTION : Changement de GET à POST pour supporter l'envoi d'un Body JSON proprement
@app.post("/audit-email")
@limiter.limit("5/minute")
async def audit_email(request: Request, input_data: EmailCheckInput, token: str = Depends(verify_api_key)):
    real_ip = get_real_user_ip(request)
    email_clean = input_data.email.lower().strip()
    logger.info(f"📧 LOG: Un audit d'email ({email_clean}) a été demandé depuis l'IP : {real_ip}")

    url = "https://api.proxynova.com/v1/breach"
    try:
        res = requests.get(url, params={"email": email_clean}, timeout=5)
        
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "breached":
                breaches = data.get("results", [])
                return {
                    "status": "danger",
                    "email": email_clean,
                    "breach_count": len(breaches),
                    "details": breaches,
                    "message": f"Cet email apparaît dans {len(breaches)} fuites de données."
                }
            else:
                return {
                    "status": "clean",
                    "email": email_clean,
                    "breach_count": 0,
                    "details": [],
                    "message": "Aucune fuite détectée pour cet email."
                }
        elif res.status_code == 404:
            return {
                "status": "clean",
                "email": email_clean,
                "breach_count": 0,
                "details": [],
                "message": "Aucune fuite détectée pour cet email (0 breach)."
            }
        else:
            return {"status": "error", "message": "Le scanner de vulnérabilités externe rencontre des difficultés."}
            
    except Exception as e:
        logger.error(f"❌ Erreur de communication Proxynova : {str(e)}")
        return {"status": "error", "message": "Le service de détection est temporairement indisponible."}


@app.post("/coffre/ajouter")
def ajouter_au_coffre(item: ItemCoffre, user_email: str = Depends(verifier_jeton_session)):
    mdp_chiffre = chiffrer_mot_de_passe(item.mot_de_passe_a_stocker)
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id FROM utilisateurs WHERE email = %s", (user_email.lower().strip(),))
        user_row = cursor.fetchone()
        
        if not user_row:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
            
        real_user_id = user_row[0]
        
        cursor.execute("""
            INSERT INTO coffre_fort (user_id, nom_site, url_site, identifiant, mot_de_passe_chiffre)
            VALUES (%s, %s, %s, %s, %s)
        """, (real_user_id, item.nom_site, item.url_site, item.identifiant, mdp_chiffre))
        
        conn.commit()
        return {"status": "success", "message": "Identifiant ajouté avec succès au coffre."}
        
    finally:
        cursor.close()
        conn.close()


@app.get("/coffre/liste")
def lister_le_coffre(user_email: str = Depends(verifier_jeton_session)):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id FROM utilisateurs WHERE email = %s", (user_email.lower().strip(),))
        user_row = cursor.fetchone()
        
        if not user_row:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
            
        real_user_id = user_row[0]
        
        cursor.execute("SELECT id, nom_site, url_site, identifiant, mot_de_passe_chiffre FROM coffre_fort WHERE user_id = %s", (real_user_id,))
        rows = cursor.fetchall()
        
        coffre_dechiffre = []
        for row in rows:
            try:
                mdp_clair = dechiffrer_mot_de_passe(row[4])
                statut_audit = verifier_fuite_mot_de_passe(mdp_clair)
            except Exception:
                mdp_clair = "[Erreur de déchiffrement]"
                statut_audit = "❌ Erreur de clés"
                
            coffre_dechiffre.append({
                "id": row[0],          
                "nom_site": row[1],    
                "url_site": row[2],    
                "identifiant": row[3], 
                "mot_de_passe": mdp_clair,
                "audit_result": statut_audit
            })
            
        return {"comptes": coffre_dechiffre}
        
    finally:
        cursor.close()
        conn.close()


@app.post("/auth/inscription")
@limiter.limit("3/minute")
def inscrire_utilisateur(request: Request, user: UserAuth, token: str = Depends(verify_api_key)):
    hash_mdp = hacher_mot_de_passe_maitre(user.password)
    email_clean = user.email.lower().strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id FROM utilisateurs WHERE email = %s", (email_clean,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Cet e-mail est déjà utilisé.")

        cursor.execute("""
            INSERT INTO utilisateurs (email, master_password_hash)
            VALUES (%s, %s) RETURNING id;
        """, (email_clean, hash_mdp))

        user_id = cursor.fetchone()[0]
        conn.commit()
        
        return {"status": "success", "user_id": user_id, "message": "Compte créé avec succès !"}
        
    finally:
        cursor.close()
        conn.close()


@app.post("/auth/connexion")
@limiter.limit("5/minute")  
def connecter_utilisateur(request: Request, user: UserAuth, token: str = Depends(verify_api_key)):
    email_clean = user.email.lower().strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id, master_password_hash FROM utilisateurs WHERE email = %s", (email_clean,))
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(status_code=401, detail="Identifiants invalides.")
            
        user_id, hash_stocke = row[0], row[1]
        
        if verifier_mot_de_passe_maitre(user.password, hash_stocke):
            payload = {
                "user_id": user_id,
                "user_email": email_clean,
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=60)).timestamp())
            }
            
            token_jwt = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
            
            return {
                "status": "success", 
                "user_id": user_id, 
                "access_token": token_jwt,
                "message": "Connexion réussie !"
            }
        else:
            raise HTTPException(status_code=401, detail="Identifiants invalides.")
            
    finally:
        cursor.close()
        conn.close()


# 🔄 CORRECTION : Utilisation du modèle ItemCoffre pour aligner les clés et
