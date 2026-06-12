import streamlit as st
import requests
import os

# Initialisation des variables de session pour l'authentification
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "user_id" not in st.session_state:
    st.session_state["user_id"] = None
if "user_email" not in st.session_state:
    st.session_state["user_email"] = ""

# Configuration de la page (Standard et propre)
st.set_page_config(page_title="CyberBrain Security Suite", page_icon="🧠", layout="centered")

# --- TITRE PRINCIPAL DE L'APPLICATION (Style standard et universel) ---
st.title("🧠 CyberBrain : Hub de Sécurité")
st.markdown("Protégez votre identité numérique grâce à notre audit de niveau professionnel.")

# --- CONFIGURATION DE L'API ---
BASE_URL = "https://cyber-checker-audit.onrender.com"
API_KEY = os.getenv("CLE_API_INTERNE", "CLE-YVES-PRO")

# En-tête global d'authentification pour l'API Gateway
headers = {"X-API-KEY": API_KEY}

# --- CRÉATION DES ONGLETS ---
tab1, tab2 = st.tabs(["🔒 Audit Mot de Passe", "📧 Audit Fuite Email"])

# ==========================================
# ONGLET 1 : AUDIT MOT DE PASSE (Sécurisé en POST)
# ==========================================
with tab1:
    st.subheader("Analyseur de Robustesse")
    pwd = st.text_input("Entrez un mot de passe à tester :", type="password", key="pwd_input")
    
    if st.button("Analyser le mot de passe", key="btn_pwd"):
        if pwd:
            with st.spinner("Analyse cryptographique en cours..."):
                try:
                    payload = {
                        "pwd": pwd,
                        "lang": "Français"
                    }
                    
                    response = requests.post(
                        f"{BASE_URL}/audit", 
                        json=payload, 
                        headers=headers
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        score = data["score"]
                        leaks = data["pwned_leaks"]
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Score d'Entropie", f"{score}/4")
                            if score < 2: st.error("⚠️ Trop vulnérable !")
                            elif score < 4: st.warning("⚠️ Robustesse moyenne")
                            else: st.success("✅ Excellent niveau")
                            
                        with col2:
                            st.metric("Fuites publiques", f"{leaks} fois")
                            if leaks > 0: st.error("🚨 Mot de passe compromis !")
                            else: st.success("✅ Aucun tag de fuite")
                        
                        st.markdown("---")
                        st.markdown("#### 💡 Recommandations CyberBrain")
                        
                        st.info(f"**Option A (Facile à retenir) :** `{data['recommendation']['passphrase_suggestion']}`")
                        st.success(f"**Option B (Sécurité maximale) :** `{data['recommendation']['random_token']}`")
                        st.caption("L'Option A utilise une logique Diceware hybride idéale pour vos comptes du quotidien. L'Option B est un jeton hautement diversifié (symboles, chiffres, casses) parfait pour un gestionnaire de mots de passe.")
                        
                    elif response.status_code == 429:
                        st.error("🛑 Rate Limit activé : Trop de requêtes. Attendez une minute.")
                    else:
                        st.error(f"Erreur technique (API) : {response.status_code}")
                except Exception as e:
                    st.error(f"Connexion au serveur impossible : {e}")
        else:
            st.warning("Veuillez saisir un mot de passe avant de lancer l'analyse.")

# ==========================================
# ONGLET 2 : AUDIT FUITE EMAIL
# ==========================================
with tab2:
    st.subheader("Détecteur de Violations d'Identité")
    email = st.text_input("Entrez votre adresse email :", placeholder="exemple@domaine.com", key="email_input")
    
    if st.button("Scanner les bases de données", key="btn_email"):
        if email:
            if "@" not in email or "." not in email:
                st.error("Le format de l'adresse email semble incorrect.")
            else:
                with st.spinner("Recherche dans les archives de fuites..."):
                    try:
                        response = requests.get(f"{BASE_URL}/audit-email", headers=headers, params={"email": email})
                        
                        if response.status_code == 200:
                            data = response.json()
                            status = data["status"]
                            
                            if status == "danger":
                                st.error(f"🚨 Alerte : {data['message']}")
                                st.markdown("#### Sites impliqués dans le piratage :")
                                for breach in data["details"]:
                                    st.write(f"• **{breach}**")
                                st.warning("👉 Action requise : Changez immédiatement les mots de passe des sites mentionnés.")
                            
                            elif status == "clean":
                                st.success(f"✅ Félicitations ! {data['message']}")
                                st.balloons()
                            else:
                                st.info(data["message"])
                                
                        elif response.status_code == 429:
                            st.error("🛑 Rate Limit activé : Trop de requêtes. Attendez une minute.")
                        else:
                            st.error(f"Erreur technique (API) : {response.status_code}")
                    except Exception as e:
                        st.error(f"Connexion au serveur impossible : {e}")
        else:
            st.warning("Veuillez entrer une adresse email à analyser.")

st.divider()
st.caption("CyberBrain Security Suite v2.5 • Hardened Framework • Propriété de Yves-Pro")

def afficher_ecran_auth(base_url, headers):
    st.subheader("🔐 Accès au Coffre-fort CyberBrain")
    
    choix_auth = st.radio("Que souhaitez-vous faire ?", ["Se connecter", "Créer un compte"], horizontal=True)
    
    email = st.text_input("Adresse e-mail :")
    password = st.text_input("Mot de passe maître :", type="password")
    
    if choix_auth == "Se connecter":
        if st.button("S'authentifier"):
            if email and password:
                try:
                    payload = {"email": email, "password": password}
                    response = requests.post(f"{base_url}/auth/connexion", json=payload, headers=headers)
                    
                    if response.status_code == 200:
                        data = response.json()
                        st.session_state["logged_in"] = True
                        st.session_state["user_id"] = data["user_id"]
                        st.session_state["user_email"] = email
                        st.success("🎉 Connexion réussie ! Chargement de votre coffre...")
                        st.rerun()
                    else:
                        st.error(f"❌ Échec de la connexion : {response.json().get('detail')}")
                except Exception as e:
                    st.error(f"Erreur de communication avec l'API : {e}")
            else:
                st.warning("Veuillez remplir tous les champs.")
                
    else:  # Créer un compte
        if st.button("Créer mon compte sécurisé"):
            if email and password:
                try:
                    payload = {"email": email, "password": password}
                    response = requests.post(f"{base_url}/auth/inscription", json=payload, headers=headers)
                    
                    if response.status_code == 200:
                        st.success("🚀 Compte créé avec succès ! Vous pouvez maintenant vous connecter.")
                    else:
                        st.error(f"❌ Erreur lors de l'inscription : {response.json().get('detail')}")
                except Exception as e:
                    st.error(f"Erreur : {e}")
            else:
                st.warning("Veuillez remplir tous les champs.")

def afficher_coffre_fort(base_url, headers):
    st.markdown(f"### 🧠 Votre Coffre-fort Sécurisé (`{st.session_state['user_email']}`)")
    
    if st.button("🚪 Se déconnecter"):
        st.session_state["logged_in"] = False
        st.session_state["user_id"] = None
        st.rerun()
        
    st.markdown("---")
    
    # --- SECTION 1 : AJOUTER UN MOT DE PASSE ---
    with st.expander("➕ Ajouter un nouvel identifiant"):
        nom_site = st.text_input("Nom du site (ex: GitHub, Netflix) :")
        url_site = st.text_input("URL du site :", placeholder="https://...")
        identifiant = st.text_input("Identifiant / Nom d'utilisateur :")
        mdp = st.text_input("Mot de passe à enregistrer :", type="password")
        
        if st.button("Chiffrer et sauvegarder"):
            if nom_site and identifiant and mdp:
                payload = {
                    "user_id": st.session_state["user_id"],
                    "nom_site": nom_site,
                    "url_site": url_site,
                    "identifiant": identifiant,
                    "mot_de_passe_a_stocker": mdp
                }
                res = requests.post(f"{base_url}/coffre/ajouter", json=payload, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    st.success(f"✅ {data['message']}")
                    st.rerun()
                else:
                    st.error("Erreur lors de la sauvegarde.")
            else:
                st.warning("Veuillez remplir les champs obligatoires (*).")

    # --- SECTION 2 : VISUALISER LES MOTS DE PASSE ENREGISTRÉS ---
    st.markdown("#### 🔑 Vos identifiants enregistrés")
    try:
        params = {"user_email": st.session_state["user_email"]}
        res = requests.get(f"{base_url}/coffre/liste", params=params, headers=headers)
        
        if res.status_code == 200:
            comptes = res.json().get("comptes", [])
            if not comptes:
                st.info("Votre coffre-fort est vide pour le moment.")
            else:
                for compte in comptes:
                    with st.container():
                        col1, col2, col3 = st.columns([2, 2, 1])
                        col1.markdown(f"**🌐 {compte['nom_site']}**\n*{compte['identifiant']}*")
                        
                        cle_unique = f"pwd_{compte['nom_site']}_{compte['identifiant']}"
                        col2.text_input("Mot de passe déchiffré :", value=compte['mot_de_passe'], type="password", key=cle_unique)
                        
                        if compte['url_site']:
                            col3.markdown(f"[Accéder au site]({compte['url_site']})")
                        
                        audit_status = compte.get("audit_result", "🔍 Non audité")
                        if "⚠️" in audit_status:
                            st.error(f"Statut : {audit_status}")
                        elif "✅" in audit_status:
                            st.success(f"Statut : {audit_status}")
                        else:
                            st.info(f"Statut : {audit_status}")
                            
                        st.markdown("---")
        else:
            st.error("Impossible de récupérer vos mots de passe.")
    except Exception as e:
        st.error(f"Erreur de chargement : {e}")

# --- MENU PRINCIPAL DE L'APPLICATION ---
st.sidebar.title("🧭 Navigation CyberBrain")
mode = st.sidebar.radio("Sélectionnez un outil :", ["🛡️ Hub d'Audit Public", "🔐 Mon Coffre-fort"])

if mode == "🛡️ Hub d'Audit Public":
    pass
elif mode == "🔐 Mon Coffre-fort":
    if not st.session_state["logged_in"]:
        afficher_ecran_auth(BASE_URL, headers)
    else:
        afficher_coffre_fort(BASE_URL, headers)
