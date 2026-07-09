from auth_utils import (
    hacher_mot_de_passe_maitre,
    verifier_mot_de_passe_maitre,
    hash_a_besoin_d_etre_mis_a_jour,
)
from fastapi import FastAPI, HTTPException, Depends, Request, Header, Path
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
import secrets
import hashlib
import requests
import zxcvbn
import os
import string
import logging
import jwt
import asyncpg
import ssl
from pydantic import BaseModel, Field, EmailStr
from crypto_utils import chiffrer_mot_de_passe, dechiffrer_mot_de_passe
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

# ==========================================
# 0. LOGS EN PREMIER
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("uvicorn.error")

# ==========================================
# 1. CONFIG DB + JWT + ADMIN
# ==========================================
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL manquant")

JWT_SECRET = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET_KEY manquant")

JWT_ALGORITHM = "HS256"
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

if not ADMIN_EMAIL:
    raise RuntimeError("ADMIN_EMAIL manquant")

# ==========================================
# 2. DB UTILS ASYNC
# ==========================================
async def get_db_connection():
    logger.info("🔌 Tentative de connexion PostgreSQL...")

    ssl_context = ssl.create_default_context()

    try:
        conn = await asyncpg.connect(
            DATABASE_URL,
            ssl=ssl_context,
            timeout=10
        )

        logger.info("✅ Connexion PostgreSQL réussie.")
        return conn

    except Exception:
        logger.exception("❌ Impossible de se connecter à PostgreSQL.")
        raise

async def init_db():
    conn = await get_db_connection()
    try:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS utilisateurs (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                master_password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS coffre_fort (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES utilisateurs(id) ON DELETE CASCADE,
                nom_site TEXT,
                url_site TEXT,
                identifiant TEXT,
                mot_de_passe_chiffre TEXT
            );
        """)
    finally:
        await conn.close()

# ==========================================
# 3. LIFESPAN
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        logger.info("🗄️ Initialisation de la base...")
        await init_db()
        logger.info("✅ Base initialisée.")
    except Exception:
        logger.exception("❌ Échec de l'initialisation de la base.")

    yield

    logger.info("🛑 Arrêt du serveur.")

app = FastAPI(title="CyberBrain API Secure Pro", debug=False, lifespan=lifespan)

# ==========================================
# 4. RATE LIMITER + CORS + HANDLER
# ==========================================
def get_real_user_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

limiter = Limiter(key_func=get_real_user_ip)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://cyber-checker-audit-interface.onrender.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"🚨 ERREUR INTERNE sur {request.url.path} : {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Erreur interne enregistrée."}
    )

# ==========================================
# 5. SÉCURITÉ API KEY + JWT + ADMIN DEPENDENCY
# ==========================================
API_KEY = os.getenv("CLE_API_INTERNE")
if not API_KEY:
    raise RuntimeError("CLE_API_INTERNE manquant")

api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)

async def verify_api_key(header_key: str = Depends(api_key_header)):
    if header_key and secrets.compare_digest(header_key, API_KEY):
        logger.info(f"🔑 ACCÈS ACCORDÉ : Clé [{header_key[:4]}****]")
        return header_key

    logger.warning("🚨 TENTATIVE D'INTRUSION : Clé invalide")
    raise HTTPException(status_code=403, detail="Clé API invalide")

def verifier_jeton_session(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer requis.")

    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["user_email"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expirée.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Session invalide.")

async def get_current_user_id(user_email: str = Depends(verifier_jeton_session)) -> int:
    conn = await get_db_connection()
    try:
        user_row = await conn.fetchrow(
            "SELECT id FROM utilisateurs WHERE email = $1",
            user_email.lower().strip()
        )
        if not user_row:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
        return user_row['id']
    finally:
        await conn.close()

async def verifier_admin(user_email: str = Depends(verifier_jeton_session)) -> str:
    email_authentifie = user_email.strip().lower()
    if not secrets.compare_digest(email_authentifie, ADMIN_EMAIL):
        logger.warning(f"🚨 TENTATIVE D'INTRUSION ADMIN : {user_email}")
        raise HTTPException(
            status_code=403,
            detail="Accès interdit : Droits administratifs insuffisants."
        )
    return email_authentifie

# ==========================================
# 6. MOTEURS + MODELES PYDANTIC
# ==========================================
def get_diceware_word(langue="Français"):
    nom_fichier = "diceware-fr.txt" if langue == "Français" else "diceware-en.txt"
    if os.path.exists(nom_fichier):
        with open(nom_fichier, "r", encoding="utf-8") as f:
            dictionnaire = [l.split()[1] for l in f.readlines() if len(l.split()) > 1]
            return secrets.choice(dictionnaire)
    return "cyber"

def generer_hybride(langue="Français"):
    mots = [
        get_diceware_word(langue).capitalize() if secrets.choice([True, False])
        else get_diceware_word(langue)
        for _ in range(4)
    ]
    separateurs = [".", ",", ";", ":", "!", "?", "£", "$"]
    phrase = "".join([
        m + (secrets.choice(separateurs) if i < 3 else "")
        for i, m in enumerate(mots)
    ])
    return phrase + secrets.choice(string.digits)

class ItemCoffre(BaseModel):
    nom_site: str
    url_site: str
    identifiant: str
    mot_de_passe_a_stocker: str

class ItemCoffreUpdate(BaseModel):
    nom_site: str
    identifiant: str
    mot_de_passe: str

class UserAuth(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=64)

class PasswordCheckInput(BaseModel):
    pwd: str = Field(..., min_length=1, max_length=128)
    lang: str = "Français"

class EmailCheckInput(BaseModel):
    email: EmailStr

# ==========================================
# 7. AUDIT HIBP
# ==========================================
def verifier_fuite_mot_de_passe(mdp_clair: str) -> str:
    try:
        if not mdp_clair or mdp_clair == "[Erreur de déchiffrement]":
            return "❌ Impossible d'auditer"

        sha1_hash = hashlib.sha1(mdp_clair.encode('utf-8')).hexdigest().upper()
        prefixe, suffixe = sha1_hash[:5], sha1_hash[5:]
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefixe}", timeout=4)

        if response.status_code == 200:
            for ligne in response.text.splitlines():
                h, nb = ligne.split(':')
                if h == suffixe:
                    return f"⚠️ Compromis (vu {nb} fois!)"
            return "✅ Sûr"
        return "⚡ Audit indisponible"
    except Exception:
        return "🔍 Non audité"

# ==========================================
# 8. ROUTES ASYNC
# ==========================================
@app.post("/audit")
@limiter.limit("5/minute")
async def audit_password(request: Request, input_data: PasswordCheckInput, token: str = Depends(verify_api_key)):
    logger.info(f"🔐 Audit pwd IP: {get_real_user_ip(request)}")
    pwd, lang = input_data.pwd, input_data.lang
    score = zxcvbn.zxcvbn(pwd)['score']
    sha1 = hashlib.sha1(pwd.encode()).hexdigest().upper()
    leaks = 0

    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{sha1[:5]}", timeout=5)
        if res.status_code == 200:
            leaks = next(
                (int(c) for h, c in (l.split(':') for l in res.text.splitlines()) if h == sha1[5:]),
                0
            )
    except Exception:
        pass

    return {
        "status": "secure" if score > 3 and leaks == 0 else "warning",
        "score": score,
        "pwned_leaks": leaks,
        "recommendation": {
            "passphrase_suggestion": generer_hybride(lang),
            "random_token": "".join(
                secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*")
                for _ in range(16)
            )
        }
    }

@app.post("/audit-email")
@limiter.limit("5/minute")
async def audit_email(request: Request, input_data: EmailCheckInput, token: str = Depends(verify_api_key)):
    email_clean = input_data.email.lower().strip()
    logger.info(f"📧 Audit email: {email_clean}")

    try:
        res = requests.get("https://api.proxynova.com/v1/breach", params={"email": email_clean}, timeout=5)
        if res.status_code == 200 and res.json().get("status") == "breached":
            breaches = res.json().get("results", [])
            return {
                "status": "danger",
                "email": email_clean,
                "breach_count": len(breaches),
                "details": breaches,
                "message": f"{len(breaches)} fuites"
            }
        return {"status": "clean", "email": email_clean, "breach_count": 0, "message": "Aucune fuite détectée."}
    except Exception as e:
        logger.error(f"❌ Proxynova: {e}")
        return {"status": "error", "message": "Service indisponible."}

@app.post("/coffre/ajouter")
async def ajouter_au_coffre(item: ItemCoffre, user_id: int = Depends(get_current_user_id)):
    conn = await get_db_connection()
    try:
        await conn.execute(
            "INSERT INTO coffre_fort (user_id, nom_site, url_site, identifiant, mot_de_passe_chiffre) VALUES ($1, $2, $3, $4, $5)",
            user_id, item.nom_site, item.url_site, item.identifiant, chiffrer_mot_de_passe(item.mot_de_passe_a_stocker)
        )
        return {"status": "success", "message": "Ajouté au coffre."}
    finally:
        await conn.close()

@app.get("/coffre/liste")
async def lister_le_coffre(user_id: int = Depends(get_current_user_id)):
    conn = await get_db_connection()
    try:
        rows = await conn.fetch(
            "SELECT id, nom_site, url_site, identifiant, mot_de_passe_chiffre FROM coffre_fort WHERE user_id = $1",
            user_id
        )
        coffre = []
        for row in rows:
            try:
                mdp_clair = dechiffrer_mot_de_passe(row['mot_de_passe_chiffre'])
                audit = verifier_fuite_mot_de_passe(mdp_clair)
            except Exception:
                mdp_clair, audit = "[Erreur de déchiffrement]", "❌ Erreur clés"

            coffre.append({
                "id": row['id'],
                "nom_site": row['nom_site'],
                "url_site": row['url_site'],
                "identifiant": row['identifiant'],
                "mot_de_passe": mdp_clair,
                "audit_result": audit
            })
        return {"comptes": coffre}
    finally:
        await conn.close()

# ==========================================
# 8.1 ROUTES CRUD : MODIFIER + SUPPRIMER
# ==========================================
@app.put("/coffre/modifier/{item_id}")
async def modifier_coffre(
    item_id: int = Path(..., ge=1),
    item: ItemCoffreUpdate =...,
    user_id: int = Depends(get_current_user_id)
):
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow(
            "SELECT id FROM coffre_fort WHERE id = $1 AND user_id = $2",
            item_id, user_id
        )
        if not row:
            raise HTTPException(status_code=404, detail="Item introuvable ou accès refusé.")

        mdp_chiffre = chiffrer_mot_de_passe(item.mot_de_passe)
        await conn.execute(
            "UPDATE coffre_fort SET nom_site = $1, identifiant = $2, mot_de_passe_chiffre = $3 WHERE id = $4",
            item.nom_site, item.identifiant, mdp_chiffre, item_id
        )
        return {"status": "success", "message": "Item modifié."}
    finally:
        await conn.close()

@app.delete("/coffre/supprimer/{item_id}")
async def supprimer_coffre(item_id: int = Path(..., ge=1), user_id: int = Depends(get_current_user_id)):
    conn = await get_db_connection()
    try:
        res = await conn.execute(
            "DELETE FROM coffre_fort WHERE id = $1 AND user_id = $2",
            item_id, user_id
        )
        if res == "DELETE 0":
            raise HTTPException(status_code=404, detail="Item introuvable ou accès refusé.")
        return {"status": "success", "message": "Item supprimé."}
    finally:
        await conn.close()

# ==========================================
# 9. AUTH + ADMIN
# ==========================================
@app.post("/auth/inscription")
@limiter.limit("3/minute")
async def inscrire_utilisateur(request: Request, user: UserAuth, token: str = Depends(verify_api_key)):
    conn = await get_db_connection()
    try:
        if await conn.fetchrow("SELECT id FROM utilisateurs WHERE email = $1", user.email.lower().strip()):
            raise HTTPException(status_code=400, detail="Email déjà utilisé.")

        user_id = await conn.fetchval(
            "INSERT INTO utilisateurs (email, master_password_hash) VALUES ($1, $2) RETURNING id;",
            user.email.lower().strip(), hacher_mot_de_passe_maitre(user.password)
        )
        return {"status": "success", "user_id": user_id, "message": "Compte créé!"}
    finally:
        await conn.close()

@app.post("/auth/connexion")
@limiter.limit("5/minute")
async def connecter_utilisateur(request: Request, user: UserAuth, token: str = Depends(verify_api_key)):
    conn = await get_db_connection()
    try:
        row = await conn.fetchrow(
            "SELECT id, master_password_hash FROM utilisateurs WHERE email = $1",
            user.email.lower().strip()
        )
        if not row or not verifier_mot_de_passe_maitre(user.password, row['master_password_hash']):
            raise HTTPException(status_code=401, detail="Identifiants invalides.")

        payload = {
            "user_id": row['id'],
            "user_email": user.email.lower().strip(),
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=60)).timestamp())
        }
        return {
            "status": "success",
            "user_id": row['id'],
            "access_token": jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM),
            "message": "Connexion réussie!"
        }
    finally:
        await conn.close()

@app.get("/admin/utilisateurs")
async def lister_utilisateurs_admin(admin_email: str = Depends(verifier_admin)):
    conn = await get_db_connection()
    try:
        rows = await conn.fetch("SELECT id, email, created_at FROM utilisateurs ORDER BY created_at DESC")
        utilisateurs = [
            {"id": r['id'], "email": r['email'], "date_inscription": r['created_at'].isoformat()}
            for r in rows
        ]
        return {"PROPRIETAIRE": "Yves-Pro", "total_utilisateurs": len(utilisateurs), "liste": utilisateurs}
    finally:
        await conn.close()
