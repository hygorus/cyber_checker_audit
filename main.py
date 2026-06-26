from fastapi import FastAPI, HTTPException, Security, Depends, Request, Header
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import JSONResponse
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
JWT_ALGORITHM = "HS256" # Algorithme standard de hachage cryptographique


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
logger = logging.getLogger("CyberBrainMonitor")

# ==========================================
# 2. CONFIGURATION DU RATE LIMITER (SLOWAPI)
# ==========================================
def get_real_user_ip(request: Request) -> str:
    # Render transmet toujours la VRAIE IP de l'utilisateur dans 'x-forwarded-for'
    # S'il y a plusieurs IP (séparées par des virgules à cause d'un attaquant qui spoof), 
    # la vraie IP de l'appelant direct est TOUJOURS la première ou la dernière selon le proxy.
    # Sur Render, c'est généralement la première adresse de la liste.
    
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # On extrait la première IP propre de la liste et on ignore le reste
        real_ip = forwarded_for.split(",")[0].strip()
        return real_ip
        
    # Repli si pas de proxy (test local)
    return request.client.host if request.client else "127.0.0.1"

# Remplace l'ancienne configuration par celle-ci
limiter = Limiter(key_func=get_real_user_ip)

# ==========================================
# 3. CONFIGURATION API ET PARAMÈTRES
# ==========================================
app = FastAPI(title="CyberBrain API Secure Pro", debug=False)

logger = logging.getLogger("uvicorn.error")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # 1. On log l'erreur réelle en local sur Render pour que TOI tu puisses réparer le bug
    logger.error(f"🚨 ERREUR INTERNE NON GÉRÉE sur {request.url.path} : {str(exc)}", exc_info=True)
    
    # 2. On renvoie une réponse totalement neutre et anonymisée au client/pirate
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

# 🔒 BLINDAGE DE SÉCURITÉ (A REPRENDRE DEPUIS TON CODE VULNÉRABLE)
API_KEY = os.getenv("CLE_API_INTERNE")

if not API_KEY:
    raise RuntimeError("🚨 ERREUR CRITIQUE : La variable d'environnement 'CLE_API_INTERNE' est introuvable. Arrêt de sécurité.")

API_KEY_NAME = "X-API-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_authorized_keys():
    # Ici, si tu utilises "CLE_API_INTERNE" comme clé unique, 
    # on s'assure qu'elle est bien chargée dans la liste des clés autorisées
    keys_raw = os.getenv("ALLOWED_API_KEYS", API_KEY)  # Utilise la variable API_KEY sécurisée en repli interne
    return [k.strip() for k in keys_raw.split(",") if k.strip()]

# ==========================================
# 4. VÉRIFICATION ET TRAÇAGE DES CLÉS API
# ==========================================
async def verify_api_key(header_key: str = Depends(api_key_header)):
    # Sécurité absolue : On compare directement avec la variable d'environnement principale
    if header_key and secrets.compare_digest(header_key, API_KEY):
        masquage_cle = f"{header_key[:4]}****"
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
    nom_site: str
    url_site: str
    identifiant: str
    mot_de_passe_a_stocker: str

class UserAuth(BaseModel):
    email: EmailStr  # 👈 TRÈS IMPORTANT : Force la validation stricte dès l'entrée
    password: str = Field(..., min_length=8, max_length=64)

class PasswordCheckInput(BaseModel):
    # On force la validation Pydantic : minimum 1 caractère, maximum 128
    pwd: str = Field(..., min_length=1, max_length=128)
    lang: str = "Français"


# ==========================================
# 6. FONCTION INTERNE : AUDIT TEMPS RÉEL (HIBP)
# ==========================================
def verifier_fuite_mot_de_passe(mdp_clair: str) -> str:
    """Vérifie de manière sécurisée (k-anonymity) si le mot de passe a fuité"""
    try:
        if not mdp_clair or mdp_clair == "[Erreur de déchiffrement]":
            return "❌ Impossible d'auditer"
            
        # 1. Hachage SHA-1 en majuscules
        sha1_hash = hashlib.sha1(mdp_clair.encode('utf-8')).hexdigest().upper()
        prefixe = sha1_hash[:5]
        suffixe = sha1_hash[5:]
        
        # 2. Requête anonyme à l'API Have I Been Pwned
        url = f"https://api.pwnedpasswords.com/range/{prefixe}"
        response = requests.get(url, timeout=4)
        
        if response.status_code == 200:
            # 3. Recherche du suffixe dans les résultats de l'API
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
        pass # Tolérance aux pannes de l'API externe

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
# 🧠 OWASP API6:2023 : On utilise le type EmailStr pour garantir que la chaîne est un email pur et dur (évite l'injection SSRF)
async def audit_email(request: Request, email: EmailStr, token: str = Depends(verify_api_key)):
    real_ip = get_real_user_ip(request)
    
    # Normalisation stricte de l'entrée utilisateur
    email_clean = email.lower().strip()
    logger.info(f"📧 LOG: Un audit d'email ({email_clean}) a été demandé depuis l'IP : {real_ip}")

    # Interrogation du scanner de fuites avec des paramètres isolés
    url = "https://api.proxynova.com/v1/breach"
    try:
        # 🧠 OWASP API6:2023 : On passe l'email via le dictionnaire 'params' pour que 'requests' encode proprement l'URL
        res = requests.get(url, params={"email": email_clean}, timeout=5) # 👈 Le timeout est obligatoire
        
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
        # 🧠 OWASP API8:2023 : On log l'erreur technique pour toi, mais on renvoie un texte neutre au client
        logger.error(f"❌ Erreur de communication Proxynova : {str(e)}")
        return {"status": "error", "message": "Le service de détection est temporairement indisponible."}


@app.post("/coffre/ajouter")
def ajouter_au_coffre(item: ItemCoffre, user_email: str = Depends(verifier_jeton_session)):
    """Route sécurisée par JWT : Ajoute un identifiant au coffre-fort de l'utilisateur connecté"""
    
    # 🧠 SÉCURITÉ CRYPTO : Chiffrement AES-Fernet avant traitement
    mdp_chiffre = chiffrer_mot_de_passe(item.mot_de_passe_a_stocker)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 🧠 1. OWASP API1:2023 PROTECTION BOLA
        # On récupère le VRAI id de l'utilisateur depuis son email extrait du jeton JWT cryptographique
        cursor.execute("SELECT id FROM utilisateurs WHERE email = %s", (user_email.lower().strip(),))
        user_row = cursor.fetchone()
        
        if not user_row:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
            
        real_user_id = user_row[0]
        
        # 🧠 2. Insertion stricte liée à l'ID interne authentifié (Le client ne choisit pas la cible)
        cursor.execute("""
            INSERT INTO coffre_fort (user_id, nom_site, url_site, identifiant, mot_de_passe_chiffre)
            VALUES (%s, %s, %s, %s, %s)
        """, (real_user_id, item.nom_site, item.url_site, item.identifiant, mdp_chiffre))
        
        conn.commit()
        return {"status": "success", "message": "Identifiant ajouté avec succès au coffre."}
        
    finally:
        # 🔒 SÉCURITÉ RESSOURCE : Libération des canaux en BDD, succès ou échec.
        cursor.close()
        conn.close()


@app.get("/coffre/liste")
def lister_le_coffre(user_email: str = Depends(verifier_jeton_session)):
    # 🧠 SÉCURITÉ ABSOLUE : 'user_email' provient DIRECTEMENT du jeton chiffré décodé et validé par FastAPI.
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 🧠 1. Sécurisation : Trouver l'ID utilisateur à partir de son email vérifié
        cursor.execute("SELECT id FROM utilisateurs WHERE email = %s", (user_email.lower().strip(),))
        user_row = cursor.fetchone()
        
        if not user_row:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
            
        real_user_id = user_row[0]
        
        # 2. On utilise cet ID interne récupéré de manière sûre pour l'interrogation
        cursor.execute("SELECT nom_site, url_site, identifiant, mot_de_passe_chiffre FROM coffre_fort WHERE user_id = %s", (real_user_id,))
        rows = cursor.fetchall()
        
        coffre_dechiffre = []
        for row in rows:
            try:
                mdp_clair = dechiffrer_mot_de_passe(row[3])
                statut_audit = verifier_fuite_mot_de_passe(mdp_clair)
            except Exception:
                mdp_clair = "[Erreur de déchiffrement]"
                statut_audit = "❌ Erreur de clés"
                
            coffre_dechiffre.append({
                "nom_site": row[0],
                "url_site": row[1],
                "identifiant": row[2],
                "mot_de_passe": mdp_clair,
                "audit_result": statut_audit
            })
            
        return {"comptes": coffre_dechiffre}
        
    finally:
        # 🔒 SÉCURITÉ RESSOURCE : Quoi qu'il arrive (succès ou erreur), la connexion est TOUJOURS fermée.
        cursor.close()
        conn.close()


@app.post("/auth/inscription")
@limiter.limit("3/minute") # 👈 Limite stricte pour la création de compte
def inscrire_utilisateur(request: Request, user: UserAuth, token: str = Depends(verify_api_key)):
    """Inscrit un nouvel utilisateur et hache son mot de passe maître"""
    hash_mdp = hacher_mot_de_passe_maitre(user.password)
    email_clean = user.email.lower().strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Vérification d'existence
        cursor.execute("SELECT id FROM utilisateurs WHERE email = %s", (email_clean,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Cet e-mail est déjà utilisé.")

        # 2. Insertion PostgreSQL avec récupération d'ID en direct
        cursor.execute("""
            INSERT INTO utilisateurs (email, master_password_hash)
            VALUES (%s, %s) RETURNING id;
        """, (email_clean, hash_mdp))

        user_id = cursor.fetchone()[0]
        conn.commit()
        
        return {"status": "success", "user_id": user_id, "message": "Compte créé avec succès !"}
        
    finally:
        # 🔒 OWASP PROTECTION RESSOURCE : Fermeture garantie de la BDD
        cursor.close()
        conn.close()


@app.post("/auth/connexion")
@limiter.limit("5/minute")  # 👈 Limite standard pour l'authentification
def connecter_utilisateur(request: Request, user: UserAuth, token: str = Depends(verify_api_key)):
    """Vérifie les identifiants et valide la connexion au coffre-fort"""
    email_clean = user.email.lower().strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id, master_password_hash FROM utilisateurs WHERE email = %s", (email_clean,))
        row = cursor.fetchone()
        
        if not row:
            # 🧠 OWASP API2:2023 : Message générique pour éviter l'énumération de comptes
            raise HTTPException(status_code=401, detail="Identifiants invalides.")
            
        user_id, hash_stocke = row[0], row[1]
        
        # Validation du mot de passe maître haché
        if verifier_mot_de_passe_maitre(user.password, hash_stocke):
            
            # 🧠 1. On prépare les données cryptographiques du badge de session
            payload = {
                "user_id": user_id,
                "user_email": email_clean,
                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=60)).timestamp())
            }
            
            # 🧠 2. On génère et signe le jeton
            token_jwt = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
            
            # 🧠 3. On retourne la réponse enrichie du JWT au frontend Streamlit
            return {
                "status": "success", 
                "user_id": user_id, 
                "access_token": token_jwt,
                "message": "Connexion réussie !"
            }
        else:
            raise HTTPException(status_code=401, detail="Identifiants invalides.")
            
    finally:
        # 🔒 OWASP PROTECTION RESSOURCE : Fermeture garantie de la BDD
        cursor.close()
        conn.close()


@app.get("/admin/utilisateurs")
def lister_utilisateurs_admin(current_user_email: str = Depends(verifier_jeton_session)):
    """Route d'administration : Droits vérifiés cryptographiquement via le jeton JWT"""
    
    # 🧠 1. Récupération de l'email officiel d'administration
    YVES_EMAIL_OFFICIEL = os.getenv("ADMIN_EMAIL", "go6axe4nh@mozmail.com").strip().lower()
    
    # 🧠 2. Normalisation de l'email extrait du JWT (Impossible à falsifier par le client)
    email_authentifie = current_user_email.strip().lower()
    
    # 🧠 3. OWASP API5:2023 - Vérification stricte du niveau d'autorisation (BFLA)
    # Comparaison mathématique à temps constant
    is_admin = secrets.compare_digest(email_authentifie, YVES_EMAIL_OFFICIEL)
    
    if not is_admin:
        # On loggue la tentative avec l'email de l'utilisateur qui a essayé de tricher
        logger.warning(f"🚨 TENTATIVE D'INTRUSION ADMIN : L'utilisateur {current_user_email} a tenté d'accéder aux droits admin.")
        raise HTTPException(
            status_code=403, 
            detail="Accès interdit : Droits administratifs insuffisants."
        )

    # 4. Requête SQL sécurisée
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id, email, created_at FROM utilisateurs")
        rows = cursor.fetchall()
        
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
        
    finally:
        # 🔒 PROTECTION RESSOURCE : Quoi qu'il arrive, on libère Supabase
        cursor.close()
        conn.close()
