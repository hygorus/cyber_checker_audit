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
import sqlite3
from pydantic import BaseModel
from crypto_utils import chiffrer_mot_de_passe
from crypto_utils import dechiffrer_mot_de_passe
from auth_utils import hacher_mot_de_passe_maitre, verifier_mot_de_passe_maitre
from database import init_db

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
# On l'initialise BIEN ICI en haut pour que les routes en dessous puissent l'utiliser !
limiter = Limiter(key_func=get_remote_address)

# ==========================================
# 3. CONFIGURATION API ET PARAMÈTRES
# ==========================================
app = FastAPI(title="CyberBrain API Secure Pro")
# Déclenche la création des tables SQLite si elles n'existent pas encore
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

# Modèle de données pour valider ce que l'interface Streamlit nous envoie
class ItemCoffre(BaseModel):
    user_id: int
    nom_site: str
    url_site: str
    identifiant: str
    mot_de_passe_a_stocker: str

@app.post("/coffre/ajouter")
def ajouter_au_coffre(item: ItemCoffre, token: str = Depends(verify_api_key)):
    # 1. On lance d'abord l'audit de robustesse sur le mot de passe soumis
    # On réutilise exactement la logique que l'on a construite ensemble
    analysis = zxcvbn.zxcvbn(item.mot_de_passe_a_stocker)
    score = analysis['score']
    
    # Génération de nos alternatives durcies au cas où l'utilisateur veut corriger son mot de passe
    passphrase_suggeree = generer_hybride("Français")
    alphabet_secu = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    token_complexe = "".join(secrets.choice(alphabet_secu) for _ in range(16))
    
    # 2. Sécurisation : On CHIFFRE le mot de passe avant l'insertion en base
    mdp_chiffre = chiffrer_mot_de_passe(item.mot_de_passe_a_stocker)
    
    # 3. Insertion dans la base de données SQLite
    try:
        conn = sqlite3.connect("cyberbrain_vault.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO coffre_fort (user_id, nom_site, url_site, identifiant, mot_de_passe_chiffre)
            VALUES (?, ?, ?, ?, ?)
        """, (item.user_id, item.nom_site, item.url_site, item.identifiant, mdp_chiffre))
        
        conn.commit()
        conn.close()
        
        # 4. On renvoie une réponse complète : confirmation + rapport de sécurité CyberBrain
        return {
            "status": "success",
            "message": f"Identifiant pour {item.nom_site} enregistré et chiffré avec succès.",
            "audit_result": {
                "score": score,
                "statut_robustesse": "Sécurisé" if score >= 3 else "Vulnérable (Pensez à le changer)",
                "alternatives_proposees": {
                    "option_a_diceware": passphrase_suggeree,
                    "option_b_complexe": token_complexe
                }
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'écriture dans le coffre-fort : {str(e)}")

@app.get("/coffre/liste")
def lister_le_coffre(user_id: int, token: str = Depends(verify_api_key)):
    """Récupère et déchiffre tous les mots de passe d'un utilisateur"""
    try:
        conn = sqlite3.connect("cyberbrain_vault.db")
        cursor = conn.cursor()
        
        # On récupère tous les sites enregistrés pour cet utilisateur
        cursor.execute("""
            SELECT id, nom_site, url_site, identifiant, mot_de_passe_chiffre 
            FROM coffre_fort 
            WHERE user_id = ?
        """, (user_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        # On reconstruit la liste en déchiffrant chaque mot de passe
        coffre_dechiffre = []
        for row in rows:
            id_item, nom_site, url_site, identifiant, mdp_chiffre = row
            
            # Utilisation de notre fonction de déchiffrement
            mdp_clair = dechiffrer_mot_de_passe(mdp_chiffre)
            
            coffre_dechiffre.append({
                "id": id_item,
                "nom_site": nom_site,
                "url_site": url_site,
                "identifiant": identifiant,
                "mot_de_passe": mdp_clair
            })
            
        return {
            "status": "success",
            "user_id": user_id,
            "total_comptes": len(coffre_dechiffre),
            "comptes": coffre_dechiffre
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de la lecture du coffre-fort : {str(e)}")

# Modèle de données pour l'authentification
class UserAuth(BaseModel):
    email: str
    password: str

@app.post("/auth/inscription")
def inscrire_utilisateur(user: UserAuth, token: str = Depends(verify_api_key)):
    """Inscrit un nouvel utilisateur et hache son mot de passe maître"""
    hash_mdp = hacher_mot_de_passe_maitre(user.password)
    
    try:
        conn = sqlite3.connect("cyberbrain_vault.db")
        cursor = conn.cursor()
        
        # On tente d'insérer le nouvel utilisateur
        cursor.execute("""
            INSERT INTO utilisateurs (email, master_password_hash)
            VALUES (?, ?)
        """, (user.email.lower().strip(), hash_mdp))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        return {
            "status": "success",
            "message": "Compte utilisateur créé avec succès !",
            "user_id": user_id
        }
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Cet e-mail est déjà enregistré.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'inscription : {str(e)}")


@app.post("/auth/connexion")
def connecter_utilisateur(user: UserAuth, token: str = Depends(verify_api_key)):
    """Vérifie les identifiants et valide la connexion au coffre-fort"""
    try:
        conn = sqlite3.connect("cyberbrain_vault.db")
        cursor = conn.cursor()
        
        # On cherche l'utilisateur par son email
        cursor.execute("SELECT id, master_password_hash FROM utilisateurs WHERE email = ?", (user.email.lower().strip(),))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            raise HTTPException(status_code=401, detail="Identifiants incorrects (email inconnu).")
            
        user_id, hash_stocke = row
        
        # Vérification cryptographique du mot de passe
        if verifier_mot_de_passe_maitre(user.password, hash_stocke):
            return {
                "status": "success",
                "message": "Connexion réussie ! Accès au coffre-fort accordé.",
                "user_id": user_id
            }
        else:
            raise HTTPException(status_code=401, detail="Identifiants incorrects (mot de passe invalide).")
            
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de la connexion : {str(e)}")

@app.get("/admin/utilisateurs")
def lister_utilisateurs_admin(token: str = Depends(verify_api_key)):
    """Route hautement sécurisée pour que Yves puisse voir les inscrits"""
    try:
        conn = sqlite3.connect("cyberbrain_vault.db")
        cursor = conn.cursor()
        
        # On récupère les IDs, les e-mails et la date de création
        cursor.execute("SELECT id, email, created_at FROM utilisateurs")
        rows = cursor.fetchall()
        conn.close()
        
        utilisateurs = []
        for row in rows:
            utilisateurs.append({
                "id": row[0],
                "email": row[1],
                "date_inscription": row[2]
            })
            
        return {
            "PROPRIÉTAIRE": "Yves-Pro",
            "total_utilisateurs": len(utilisateurs),
            "liste": utilisateurs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
