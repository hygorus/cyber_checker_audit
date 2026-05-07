import streamlit as st
import hashlib
import requests
import zxcvbn
import secrets
import string
import os

# --- CONFIGURATION DE LA PAGE ---
st.set_page_config(page_title="CyberBrain Auditor", page_icon="🛡️")

# --- MOTEURS DE GÉNÉRATION AMÉLIORÉS ---

def generer_passphrase_diceware(langue="Français", nb_mots=4):
    """Génère une passphrase basée sur la langue choisie."""
    # Sélection du fichier selon la langue
    nom_fichier = "diceware-fr.txt" if langue == "Français" else "diceware-en.txt"
    
    if os.path.exists(nom_fichier):
        with open(nom_fichier, "r", encoding="utf-8") as f:
            dictionnaire = [ligne.split()[1] if len(ligne.split()) > 1 else ligne.strip() 
                           for ligne in f if ligne.strip()]
    else:
        # Secours si le fichier est absent
        dictionnaire = ["security", "vault", "shield", "cyber"] if langue == "Anglais" else ["securite", "coffre", "bouclier", "cyber"]

    mots = [secrets.choice(dictionnaire) for _ in range(nb_mots)]
    separateurs = [".", ",", ";", ":", "!", "?", "£", "$"]
    
    phrase = ""
    for i, mot in enumerate(mots):
        mot_formatte = mot.capitalize() if secrets.choice([True, False]) else mot
        phrase += mot_formatte
        if i < len(mots) - 1:
            phrase += secrets.choice(separateurs)
            
    return phrase + secrets.choice(string.digits)

def generer_mdp_complexe(longueur=16):
    caracteres = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|"
    return ''.join(secrets.choice(caracteres) for _ in range(longueur))

# --- FONCTION D'AUDIT API ---

def verifier_fuites(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefixe, suffixe = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefixe}"
    try:
        reponse = requests.get(url)
        if reponse.status_code == 200:
            lignes = reponse.text.splitlines()
            for ligne in lignes:
                h, count = ligne.split(':')
                if h == suffixe: return int(count)
        return 0
    except: return -1

# --- INTERFACE UTILISATEUR ---

st.title("🛡️ CyberBrain : Auditeur de Sécurité")

# Choix de la langue de l'interface et du générateur
langue_interface = st.sidebar.selectbox("Langue / Language", ("Français", "Anglais"))

label_input = "Entrez le mot de passe à tester :" if langue_interface == "Français" else "Enter the password to test:"
mdp = st.text_input(label_input, type="password")

if mdp:
    res = zxcvbn.zxcvbn(mdp)
    score = res['score']
    temps_crack = res['crack_times_display']['offline_fast_hashing_1e10_per_second']
    fuites = verifier_fuites(mdp)
    
    # Affichage des métriques
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Score", f"{score}/4")
        st.progress(score * 25)
    with col2:
        if fuites > 0: st.error(f"⚠️ {fuites:,} brèches !")
        elif fuites == 0: st.success("✅ Sécurisé")
    
    st.write(f"**Estimation de craquage :** {temps_crack}")

    # --- NOUVEAU SEUIL DE SÉCURITÉ (Score <= 3) ---
    if score <= 3:
        st.divider()
        msg_alerte = "🚨 Amélioration recommandée pour une sécurité maximale." if langue_interface == "Français" else "🚨 Improvement recommended for maximum security."
        st.warning(msg_alerte)
        
        # Options de génération
        choix = st.radio(
            "Type de remplacement :" if langue_interface == "Français" else "Replacement type:",
            ("Passphrase Narrative", "Code Aléatoire / Random Code")
        )
        
        if "Passphrase" in choix:
            # On utilise la langue choisie dans la barre latérale pour le Diceware
            nouveau = generer_passphrase_diceware(langue=langue_interface)
        else:
            nouveau = generer_mdp_complexe()
            
        st.code(nouveau, language="bash")
