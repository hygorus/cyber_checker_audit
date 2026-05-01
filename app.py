import streamlit as st
import hashlib
import requests
from zxcvbn import zxcvbn

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