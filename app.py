import string
import secrets
import streamlit as st
import hashlib
import requests
from zxcvbn import zxcvbn
import os

def generer_passphrase_complexe(nb_mots=4):
    # Procédure de lecture sécurisée du fichier
    chemin_fichier = "diceware-fr.txt"
    
    if os.path.exists(chemin_fichier):
        with open(chemin_fichier, "r", encoding="utf-8") as f:
            dictionnaire = []
            for ligne in f:
                # Analyse de ligne : on sépare par les espaces/tabulations
                parties = ligne.split()
                if len(parties) >= 2:
                    # Si la ligne est "25166 emission", on ne prend que "emission"
                    # En général, dans Diceware, le mot est le DEUXIÈME élément
                    mot = parties[1].strip()
                    dictionnaire.append(mot)
                elif len(parties) == 1:
                    # Si la ligne n'a que le mot
                    dictionnaire.append(parties[0].strip())
    else:
        dictionnaire = ["cyber", "securite", "expert", "code"]

    # 1. Sélection cryptographique parmi les 7 776 mots
    mots = [secrets.choice(dictionnaire) for _ in range(nb_mots)]
    
    # 2. Injection de complexité (Chiffre et Symbole)
    chiffre = secrets.choice(string.digits)
    symbole = secrets.choice("!@#$%&*?")
    
    passphrase = "-".join(mots)
    passphrase = passphrase.replace("-", symbole, 1)
    passphrase += chiffre
    
    return passphrase

# Configuration de la page
st.set_page_config(page_title="CyberBrain Audit", page_icon="🛡")

st.title("🛡 CyberBrain : Auditeur de Sécurité")
st.write("Vérifiez la robustesse et l'intégrité de vos mots de passe.")

# Champ de saisie
mdp = st.text_input("Entrez le mot de passe à tester :", type="password")

if mdp:
    # 1. Analyse de complexité
    res = zxcvbn(mdp)
    score = res['score']
    
    # 2. Analyse de brèches (on réutilise ta logique SHA-1)
    sha1 = hashlib.sha1(mdp.encode('utf-8')).hexdigest().upper()
    prefixe, suffixe = sha1[:5], sha1[5:]
    reponse = requests.get(f"https://api.pwnedpasswords.com/range/{prefixe}")
    
    fuites = 0
    for ligne in reponse.text.splitlines():
        h, count = ligne.split(':')
        if h == suffixe:
            fuites = int(count)
            break

    # --- AFFICHAGE DES RÉSULTATS ---
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Score de Robustesse", f"{score}/4")
        st.progress(score * 25)
        
    with col2:
        if fuites > 0:
            st.error(f"⚠️ Trouvé dans {fuites} brèches !")
        else:
            st.success("✅ Aucune fuite détectée.")

    st.subheader("Analyse détaillée")
    st.write(f"**Temps estimé pour craquer :** {res['crack_times_display']['offline_fast_hashing_1e10_per_second']}")
    
    if res['feedback']['suggestions']:
        for s in res['feedback']['suggestions']:
            st.info(f"Conseil : {s}")
    # --- AJOUT DE LA PHASE 4 : REMÉDIATION ---
    if score == 0:
        st.divider() # Ajoute une ligne de séparation propre
        st.warning("⚠️ Alerte de vulnérabilité critique")
        nouvelle_pass = generer_passphrase_complexe()
        st.write(f"**Alternative sécurisée recommandée :** `{nouvelle_pass}`")
        st.caption("Cette passphrase est composée de mots aléatoires. Elle est plus longue, plus sûre et plus facile à mémoriser.")
