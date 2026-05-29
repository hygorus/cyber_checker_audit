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
import logging
from pydantic import BaseModel
from database import get_db_connection, init_db
from crypto_utils import chiffrer_mot_de_passe, dechiffrer_mot_de_passe
from auth_utils import hacher_mot_de_passe_maitre, verifier_mot_de_passe_maitre

# ==========================================
# 1. CONFIGURATION DU MONITORING (LOGS)
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("CyberBrainMonitor")

# ==========================================
# 2. CONFIGURATION DU RATE LIMITER (SLOWAPI)
# ==========================================
def get_real_user_ip(request: Request) -> str:
    # Render transmet la vraie IP du visiteur dans cet en-tête
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # On prend la première IP de la liste (au cas où il y en a plusieurs)
        return forwarded.split(",")[0].strip()
    # Si on est en local et que l'en-tête n'existe pas, on prend l'IP standard
    return request.client.host if request.client else "127.0.0.1"

# Remplace l'ancienne configuration par celle-ci
limiter = Limiter(key_func=get_real_user_ip)

# ==========================================
# 3. CONFIGURATION API ET PARAMÈTRES
# ==========================================
app = FastAPI(title="CyberBrain API Secure Pro")

# Déclenche la création des tables sur PostgreSQL (Supabase)
init_db()

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_authorized_keys():
    keys_raw = os.getenv("ALLOWED_API_KEYS", "")
    return [k.strip() for k in keys_raw.split(",") if k.strip()]

# ==========================================
# 4. VÉRIFICATION ET TRAÇAGE DES CLÉS API
# ==========================================
async def verify_api_key(header_key: str = Depends(api_key_header)):
    authorized_keys = get_authorized_keys()
    is_valid = any(secrets.compare_digest(header_key or "", k) for k in authorized_keys)
    
    if is_valid:
        masquage_cle = f"{header_key[:4]}****" if header_key else "INCONNUE"
        logger.info(f"🔑 ACCÈS ACCORDÉ : La clé [{masquage_cle}] a validé une requête.")
        return header_key
        
    logger.warning(f"🚨 TENTATIVE D'INTRUSION : Une clé invalide ou manquante a été soumise.")
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
    user_id: int
    nom_site: str
    url_site: str
    identifiant: str
    mot_de_passe_a_stocker: str

class UserAuth(BaseModel):
    email: str
    password: str


# ==========================================
# 6. ROUTES DE L'APPLICATION
# ==========================================

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


@app.post("/coffre/ajouter")
def ajouter_au_coffre(item: ItemCoffre, token: str = Depends(verify_api_key)):
    analysis = zxcvbn.zxcvbn(item.mot_de_passe_a_stocker)
    score = analysis['score']
    
    passphrase_suggeree = generer_hybride("Français")
    alphabet_secu = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    token_complexe = "".join(secrets.choice(alphabet_secu) for _ in range(16))
    
    # Sécurisation : Chiffrement AES-Fernet avant l'envoi vers la base
    mdp_chiffre = chiffrer_mot_de_passe(item.mot_de_passe_a_stocker)
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO coffre_fort (user_id, nom_site, url_site, identifiant, mot_de_passe_chiffre)
            VALUES (%s, %s, %s, %s, %s)
        """, (item.user_id, item.nom_site, item.url_site, item.identifiant, mdp_chiffre))
        conn.commit()
        cursor.close()
        conn.close()
        return {"status": "success", "message": "Identifiant ajouté avec succès au coffre."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur d'écriture BDD : {str(e)}")


@app.get("/coffre/liste")
def lister_le_coffre(user_id: int, token: str = Depends(verify_api_key)):
    """Récupère et déchiffre tous les mots de passe d'un utilisateur"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT nom_site, url_site, identifiant, mot_de_passe_chiffre FROM coffre_fort WHERE user_id = %s", (user_id,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        coffre_dechiffre = []
        for row in rows:
            try:
                mdp_clair = dechiffrer_mot_de_passe(row[3])
            except:
                mdp_clair = "[Erreur de déchiffrement]"
                
            coffre_dechiffre.append({
                "nom_site": row[0],
                "url_site": row[1],
                "identifiant": row[2],
                "mot_de_passe": mdp_clair
            })
        return coffre_dechiffre
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/auth/inscription")
def inscrire_utilisateur(user: UserAuth, token: str = Depends(verify_api_key)):
    """Inscrit un nouvel utilisateur et hache son mot de passe maître"""
    hash_mdp = hacher_mot_de_passe_maitre(user.password)
    email_clean = user.email.lower().strip()
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Vérification d'existence
        cursor.execute("SELECT id FROM utilisateurs WHERE email = %s", (email_clean,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            raise HTTPException(status_code=400, detail="Cet e-mail est déjà utilisé.")

        # Insertion PostgreSQL avec récupération d'ID en direct
        cursor.execute("""
            INSERT INTO utilisateurs (email, master_password_hash)
            VALUES (%s, %s) RETURNING id;
        """, (email_clean, hash_mdp))

        user_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
        conn.close()
        return {"status": "success", "user_id": user_id, "message": "Compte créé avec succès !"}
    except Exception as e:
        if "HTTPException" in str(type(e)): raise e
        raise HTTPException(status_code=500, detail=f"Erreur d'inscription : {str(e)}")


@app.post("/auth/connexion")
def connecter_utilisateur(user: UserAuth, token: str = Depends(verify_api_key)):
    """Vérifie les identifiants et valide la connexion au coffre-fort"""
    email_clean = user.email.lower().strip()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, master_password_hash FROM utilisateurs WHERE email = %s", (email_clean,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=401, detail="Identifiants invalides.")
            
        user_id, hash_stocke = row[0], row[1]
        
        # Validation du mot de passe maître haché
        if verifier_mot_de_passe_maitre(user.password, hash_stocke):
            return {"status": "success", "user_id": user_id, "message": "Connexion réussie !"}
        else:
            raise HTTPException(status_code=401, detail="Identifiants invalides.")
    except Exception as e:
        if "HTTPException" in str(type(e)): raise e
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/utilisateurs")
def lister_utilisateurs_admin(token: str = Depends(verify_api_key)):
    """Route hautement sécurisée pour que Yves puisse voir les inscrits"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, created_at FROM utilisateurs")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        utilisateurs = []
        for row in rows:
            utilisateurs.append({
                "id": row[0],
                "email": row[1],
                "date_inscription": str(row[2])
            })
            
        return {
            "PROPRIÉTAIRE": "Yves-Pro",
            "total_utilisateurs": len(utilisateurs),
            "liste": utilisateurs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
