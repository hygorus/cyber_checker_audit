import streamlit as st
import hashlib
import requests
import zxcvbn
import secrets
import string
import os

# --- CONFIGURATION DE LA PAGE ---
st.set_page_config(page_title="CyberBrain Auditor", page_icon="🛡️")

# --- MOTEURS DE GÉNÉRATION (PHASE 4 AMÉLIORÉE) ---

def generer_passphrase_diceware(nb_mots=4):
    """Génère une passphrase narrative avec séparateurs variés et majuscules."""
    chemin_fichier = "diceware-fr.txt"
    if os.path.exists(chemin_fichier):
        with open(chemin_fichier, "r", encoding="utf-8") as f:
            # Nettoyage intelligent : on ignore l'index numérique si présent
            dictionnaire = []
            for ligne in f:
                parties = ligne.split()
                if len(parties) >= 2:
                    dictionnaire.append(parties[1].strip())
                elif len(parties) == 1:
                    dictionnaire.append(parties[0].strip())
    else:
        # Secours si le fichier est absent
        dictionnaire = ["cyber", "securite", "expert", "reseau", "code", "sentinel"]

    mots = [secrets.choice(dictionnaire) for _ in range(nb_mots)]
    separateurs = [".", ",", ";", ":", "!", "?", "£", "$"]
    
    phrase = ""
    for i, mot in enumerate(mots):
        # Majuscule aléatoire pour le style "Phrase"
        mot_formatte = mot.capitalize() if secrets.choice([True, False]) else mot
        phrase += mot_formatte
        if i < len(mots) - 1:
            phrase += secrets.choice(separateurs)
            
    return phrase + secrets.choice(string.digits)

def generer_mdp_complexe(longueur=16):
    """Génère une chaîne purement aléatoire de haute densité."""
    caracteres = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|"
    return ''.join(secrets.choice(caracteres) for _ in range(longueur))

# --- FONCTIONS D'AUDIT (MOTEUR CENTRAL) ---

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
                if h == suffixe:
                    return int(count)
        return 0
    except:
        return -1

# --- INTERFACE UTILISATEUR ---

st.title("🛡️ CyberBrain : Auditeur de Sécurité")
st.write("Vérifiez la robustesse et l'intégrité de vos accès en temps réel.")

mdp = st.text_input("Entrez le mot de passe à tester :", type="password")

if mdp:
    # 1. Analyse de robustesse
    res = zxcvbn.zxcvbn(mdp)
    score = res['score']
    # Correction de la coupure de ligne pour le temps de crack
    temps_crack = res['crack_times_display']['offline_fast_hashing_1e10_per_second']
    
    # 2. Vérification des fuites
    fuites = verifier_fuites(mdp)
    
    # 3. Affichage des métriques
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Score de Robustesse", f"{score}/4")
        st.progress(score * 25)
        
    with col2:
        if fuites > 0:
            st.error(f"⚠️ Trouvé dans {fuites:,} brèches !")
        elif fuites == 0:
            st.success("✅ Aucune fuite détectée.")
        else:
            st.warning("Connexion API impossible.")

    st.subheader("Analyse détaillée")
    st.write(f"**Temps estimé pour craquer :** {temps_crack}")
    
    if res['feedback']['suggestions']:
        for s in res['feedback']['suggestions']:
            st.info(f"Conseil : {s}")

    # --- PHASE 4 : REMÉDIATION ET GÉNÉRATION ---
    if score <= 1:
        st.divider()
        st.warning("🚨 Votre mot de passe actuel est trop vulnérable.")
        
        st.subheader("Générateur de remplacement sécurisé")
        choix = st.radio(
            "Quelle stratégie préférez-vous ?",
            ("Passphrase Narrative (Mémorisable)", "Code Aléatoire (Gestionnaire)")
        )
        
        if choix == "Passphrase Narrative (Mémorisable)":
            nouveau = generer_passphrase_diceware()
            st.write("**Suggestion (Style Phrase) :**")
        else:
            nouveau = generer_mdp_complexe()
            st.write("**Suggestion (Haute Densité) :**")
            
        st.code(nouveau, language="bash")
        st.caption("Copiez ce secret et enregistrez-le dans un endroit sûr.")
