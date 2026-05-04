import string
import secrets
import streamlit as st
import hashlib
import requests
from zxcvbn import zxcvbn

def generer_passphrase_complexe(nb_mots=4):
    dictionnaire = ["abricot", "amiral", "banquise", "boussole", "cactus", "caillou", "calcaire", "camion", 
        "canard", "capsule", "carton", "cascade", "ceinture", "cerise", "charbon", "clavier", 
        "cloche", "colline", "cristal", "cuisine", "dauphin", "dentelle", "desert", "disque", 
        "domino", "echarpe", "eclair", "ecureuil", "aimant", "enigme", "epaule", "espace", 
        "etoile", "falaise", "fantome", "farine", "flamme", "fleuve", "foret", "fraise", 
        "gant", "girafe", "glacier", "guitare", "hamac", "harpe", "herisson", "hibou", 
        "horizon", "horloge", "image", "insecte", "ivoire", "jardin", "jungle", "kangourou", 
        "labyrinthe", "lampe", "lecture", "lezard", "lion", "locomotive", "lumiere", "lune", 
        "mairie", "manchot", "marmotte", "miroir", "montagne", "moustique", "navire", "nuage", 
        "oiseau", "orange", "orchidee", "ouragan", "papillon", "parapluie", "pastèque", "pelle", 
        "phare", "piano", "pilote", "pinceau", "planete", "plateau", "poisson", "polaire", 
        "prairie", "quartz", "radar", "radeau", "raisin", "renard", "requin", "rideau", 
        "robot", "rocher", "ruisseau", "sable", "saison", "sapin", "satellite", "sauvage", 
        "scooter", "serpent", "silence", "soleil", "sommet", "source", "spectacle", "sphère", 
        "tambour", "tempête", "theâtre", "tigre", "tomate", "torche", "toupie", "tunnel", 
        "univers", "ustensile", "valise", "vampire", "vitesse", "volcan", "wagon", "xylophone", "zebre", "zenith"] # (Utilise ta liste complète ici)
    
    # 1. Sélection des mots
    mots = [secrets.choice(dictionnaire) for _ in range(nb_mots)]
    
    # 2. Ajout de la complexité (Chiffre et Symbole)
    chiffre = secrets.choice(string.digits)     # Choisit un chiffre entre 0 et 9
    symbole = secrets.choice("!@#$%&*?")        # Choisit un symbole fort
    
    # On remplace un séparateur par un symbole et on colle le chiffre à un mot
    passphrase = "-".join(mots)
    passphrase = passphrase.replace("-", symbole, 1) # Remplace le 1er tiret par le symbole
    passphrase += chiffre                            # Ajoute le chiffre à la fin
    
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
