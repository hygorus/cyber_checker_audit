from fastapi import FastAPI, Query
import hashlib
import requests
import zxcvbn
import secrets
import string
import os

app = FastAPI(title="CyberBrain API", description="API d'audit et de génération de secrets")

# --- MOTEURS DE GÉNÉRATION ---

def get_diceware_word(langue="Français"):
    nom_fichier = "diceware-fr.txt" if langue == "Français" else "diceware-en.txt"
    if os.path.exists(nom_fichier):
        with open(nom_fichier, "r", encoding="utf-8") as f:
            lines = f.readlines()
            # On extrait le mot (deuxième colonne)
            dictionnaire = [l.split()[1] for l in lines if len(l.split()) > 1]
            return secrets.choice(dictionnaire)
    return "cyber" # Secours

def generer_hybride(langue="Français"):
    mots = [get_diceware_word(langue).capitalize() if secrets.choice([True, False]) 
            else get_diceware_word(langue) for _ in range(4)]
    separateurs = [".", ",", ";", ":", "!", "?", "£", "$"]
    phrase = ""
    for i, mot in enumerate(mots):
        phrase += mot
        if i < 3: phrase += secrets.choice(separateurs)
    return phrase + secrets.choice(string.digits)

# --- FONCTIONS D'AUDIT ---

def check_pwned(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    if res.status_code == 200:
        for line in res.text.splitlines():
            h, count = line.split(':')
            if h == suffix: return int(count)
    return 0

# --- POINTS D'ENTRÉE (ENDPOINTS) ---

@app.get("/audit")
def audit_password(pwd: str, lang: str = "Français"):
    # 1. Analyse
    analysis = zxcvbn.zxcvbn(pwd)
    score = analysis['score']
    leaks = check_pwned(pwd)
    
    # 2. Génération de recommandation si score <= 3
    suggestion = None
    if score <= 3:
        suggestion = {
            "passphrase_narrative": generer_hybride(lang),
            "random_code": ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        }

    return {
        "status": "danger" if score <= 1 or leaks > 0 else "warning" if score <= 3 else "secure",
        "score": score,
        "pwned_leaks": leaks,
        "crack_time": analysis['crack_times_display']['offline_fast_hashing_1e10_per_second'],
        "recommendation": suggestion
    }