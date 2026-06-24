import streamlit as st
import requests
import os

# ==========================================
# 1. INITIALISATION STRICTE DE LA SESSION
# ==========================================
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "user_id" not in st.session_state:
    st.session_state["user_id"] = None
if "user_email" not in st.session_state:
    st.session_state["user_email"] = ""
if "session_jwt" not in st.session_state:  # 👈 CORRECTION : Évite le KeyError au premier démarrage
    st.session_state["session_jwt"] = None

# Configuration de la page (Standard et propre)
st.set_page_config(page_title="CyberBrain Security Suite", page_icon="🧠", layout="centered")

# --- TITRE PRINCIPAL DE L'APPLICATION ---
st.title("🧠 CyberBrain : Hub de Sécurité")
st.markdown("Protégez votre identité numérique grâce à notre audit de niveau professionnel.")

# --- CONFIGURATION DE L'API ---
BASE_URL = "https://cyber-checker-audit.onrender.com"

# Blindé contre les fuites sur GitHub
API_KEY = os.getenv("CLE_API_INTERNE")

if not API_KEY:
    raise RuntimeError("🚨 ERREUR CRITIQUE : La variable d'environnement 'CLE_API_INTERNE' est introuvable. Arrêt de sécurité.")

# En-tête global d'authentification pour l'API Gateway
headers = {"X-API-KEY": API_KEY}

# ==========================================
# 2. ESPACE D'ADMINISTRATION
# ==========================================
def afficher_panneau_admin(base_url):
    st.subheader("👨‍💻 Espace d'Administration Général")
    st.caption("Réservé exclusivement à l'administrateur. Autorisation validée par signature cryptographique (JWT).")
    
    if st.button("🔄 Charger la liste des utilisateurs"):
        with st.spinner("Interrogation de la base de données..."):
            try:
                # Configuration des headers sécurisés avec le JWT
                headers_admin = {
                    "X-API-KEY": API_KEY,
                    "Authorization": f"Bearer {st.session_state['session_jwt']}"
                }
                
                res = requests.get(f"{base_url}/admin/utilisateurs", headers=headers_admin)
                
                if res.status_code == 200:
                    data = res.json()
                    st.success(f"Données récupérées avec succès. Propriétaire : {data.get('PROPRIÉTAIRE', 'Admin')}")
                    st.metric("Total des utilisateurs inscrits", data.get("total_utilisateurs", 0))
                    
                    # Affichage sous forme de tableau propre
                    st.dataframe(data.get("liste", []), use_container_width=True)
                else:
                    st.error(f"🛑 Accès refusé par le serveur API (Code {res.status_code})")
            except Exception as e:
                st.error(f"Erreur de communication : {e}")

# ==========================================
# 3. HUB D'AUDIT PUBLIC (MOT DE PASSE & EMAIL)
# ==========================================
def afficher_hub_public():
    tab1, tab2 = st.tabs(["🔒 Audit Mot de Passe", "📧 Audit Fuite Email"])

    # --- ONGLET 1 : AUDIT MOT DE PASSE ---
    with tab1:
        st.subheader("Analyseur de Robustesse")
        pwd = st.text_input("Entrez un mot de passe à tester :", type="password", key="pwd_input")
        
        if st.button("Analyser le mot de passe", key="btn_pwd"):
            if pwd:
                with st.spinner("Analyse cryptographique en cours..."):
                    try:
                        payload = {"pwd": pwd, "lang": "Français"}
                        response = requests.post(f"{BASE_URL}/audit", json=payload, headers=headers)
                        
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
                            st.caption("L'Option A utilise une logique Diceware hybride idéale pour vos comptes du quotidien. L'Option B est un jeton hautement diversifié parfait pour un gestionnaire de mots de passe.")
                            
                        elif response.status_code == 429:
                            st.error("🛑 Rate Limit activé : Trop de requêtes. Attendez une minute.")
                        else:
                            st.error(f"Erreur technique (API) : {response.status_code}")
                    except Exception as e:
                        st.error(f"Connexion au serveur impossible : {e}")
            else:
                st.warning("Veuillez saisir un mot de passe avant de lancer l'analyse.")

    # --- ONGLET 2 : AUDIT FUITE EMAIL ---
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

# ==========================================
# 4. CRÉATION DE COMPTE / ÉCRAN DE CONNEXION
# ==========================================
def afficher_ecran_auth(base_url, headers_api_globaux):
    st.subheader("🔐 Accès au Coffre-fort CyberBrain")
    
    choix_auth = st.radio("Que souhaitez-vous faire ?", ["Se connecter", "Créer un compte"], horizontal=True)
    
    with st.form(key="formulaire_authentification"):
        email = st.text_input("Adresse e-mail :")
        password = st.text_input("Mot de passe maître :", type="password")
        
        texte_bouton = "S'authentifier" if choix_auth == "Se connecter" else "Créer mon compte sécurisé"
        soumis = st.form_submit_button(label=texte_bouton)
        
    if soumis:
        if email and password:
            if choix_auth == "Se connecter":
                try:
                    payload = {"email": email, "password": password}
                    response = requests.post(f"{base_url}/auth/connexion", json=payload, headers=headers_api_globaux)
                    
                    if response.status_code == 200:
                        data = response.json()
                        st.session_state["logged_in"] = True
                        st.session_state["session_jwt"] = data["access_token"]
                        st.session_state["user_email"] = email.strip().lower()
                        st.rerun()  # Redirection instantanée vers le coffre déverrouillé
                    else:
                        st.error(f"❌ Échec de la connexion : {response.json().get('detail')}")
                except Exception as e:
                    st.error(f"Erreur de communication avec l'API : {e}")
                    
            else:  # Créer un compte
                try:
                    payload = {"email": email, "password": password}
                    response = requests.post(f"{base_url}/auth/inscription", json=payload, headers=headers_api_globaux)
                    
                    if response.status_code == 200:
                        st.success("🚀 Compte créé avec succès ! Vous pouvez maintenant basculer sur 'Se connecter'.")
                    else:
                        st.error(f"❌ Erreur lors de l'inscription : {response.json().get('detail')}")
                except Exception as e:
                    st.error(f"Erreur : {e}")
        else:
            st.warning("Veuillez remplir tous les champs.")

# ==========================================
# 5. ESPACE COFFRE-FORT (SÉCURISÉ PAR JWT)
# ==========================================
def afficher_coffre_fort(base_url, headers_api_globaux):
    st.markdown(f"### 🧠 Votre Coffre-fort Sécurisé (`{st.session_state['user_email']}`)")
    
    if st.button("🚪 Se déconnecter"):
        st.session_state["logged_in"] = False
        st.session_state["session_jwt"] = None
        st.session_state["user_email"] = ""
        st.rerun()
        
    st.markdown("---")
    
    # --- SECTION A : AJOUTER UN IDENTIFIANT ---
    with st.expander("➕ Ajouter un nouvel identifiant"):
        nom_site = st.text_input("Nom du site (ex: GitHub, Netflix) :")
        url_site = st.text_input("URL du site :", placeholder="https://...")
        identifiant = st.text_input("Identifiant / Nom d'utilisateur :")
        mdp = st.text_input("Mot de passe à enregistrer :", type="password")
        
        if st.button("Chiffrer et sauvegarder"):
            if nom_site and identifiant and mdp:
                headers_requete = {
                    "X-API-KEY": API_KEY,
                    "Authorization": f"Bearer {st.session_state['session_jwt']}"
                }
                payload = {
                    "nom_site": nom_site,
                    "url_site": url_site,
                    "identifiant": identifiant,
                    "mot_de_passe_a_stocker": mdp
                }
                res = requests.post(f"{base_url}/coffre/ajouter", json=payload, headers=headers_requete)
                if res.status_code == 200:
                    st.success("✅ Identifiant ajouté avec succès au coffre.")
                    st.rerun()
                else:
                    st.error("Erreur lors de la sauvegarde.")
            else:
                st.warning("Veuillez remplir les champs obligatoires.")

    # --- SECTION B : VISUALISER LES ÉLÉMENTS ---
    st.markdown("#### 🔑 Vos identifiants enregistrés")
    try:
        headers_requete = {
            "X-API-KEY": API_KEY, 
            "Authorization": f"Bearer {st.session_state['session_jwt']}" 
        }
        
        res = requests.get(f"{base_url}/coffre/liste", headers=headers_requete)
        
        if res.status_code == 200:
            comptes = res.json().get("comptes", [])
            if not comptes:
                st.info("Votre coffre-fort est vide pour le moment.")
            else:
                # Utilisation de l'index d'énumération pour sécuriser l'unicité des clés Streamlit
                for idx, compte in enumerate(comptes):
                    with st.container():
                        col1, col2, col3 = st.columns([2, 2, 1])
                        col1.markdown(f"**🌐 {compte['nom_site']}**\n*{compte['identifiant']}*")
                        
                        cle_unique = f"pwd_{idx}_{compte['nom_site']}"
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
                        
        # 👈 CORRECTION ALIGNEMENT INDENTATION : Forcer la déconnexion UX propre si le JWT expire (401)
        elif res.status_code == 401:
            st.error("🔒 Votre session a expiré. Veuillez vous reconnecter.")
            st.session_state["logged_in"] = False
            st.session_state["session_jwt"] = None
            st.session_state["user_email"] = ""
            st.rerun()
        else:
            st.error("Impossible d'accéder au coffre-fort (Erreur serveur).")
    except Exception as e:
        st.error(f"Erreur de réseau : {e}")

# ==========================================
# 6. ARCHITECTURE DE NAVIGATION (SIDEBAR)
# ==========================================
st.sidebar.title("🧭 Navigation CyberBrain")

# Récupération dynamique de l'email d'administration depuis l'environnement (ou repli par défaut)
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "yves@cyber.pro").strip().lower()

liste_choix = ["🛡️ Hub d'Audit Public", "🔐 Mon Coffre-fort"]

# Contrôle d'affichage conditionnel pour l'espace d'administration
if st.session_state["logged_in"] and st.session_state["user_email"] == ADMIN_EMAIL:
    liste_choix.append("👨‍💻 Panneau Admin")

mode = st.sidebar.radio("Sélectionnez un outil :", liste_choix)

if mode == "🛡️ Hub d'Audit Public":
    afficher_hub_public()
    
elif mode == "🔐 Mon Coffre-fort":
    if not st.session_state["logged_in"]:
        afficher_ecran_auth(BASE_URL, headers)
    else:
        afficher_coffre_fort(BASE_URL, headers)

elif mode == "👨‍💻 Panneau Admin":
    if st.session_state["logged_in"] and st.session_state["user_email"] == ADMIN_EMAIL:
        afficher_panneau_admin(BASE_URL)
    else:
        st.error("Accès interdit.")

st.divider()
st.caption("CyberBrain Security Suite v2.5 • Hardened Framework • Propriété de l'Administrateur")
