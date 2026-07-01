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
if "session_jwt" not in st.session_state:  
    st.session_state["session_jwt"] = None

# Configuration de la page
st.set_page_config(page_title="CyberBrain Security Suite", page_icon="🧠", layout="centered")

# --- TITRE PRINCIPAL ---
st.title("🧠 CyberBrain : Hub de Sécurité")
st.markdown("Protégez votre identité numérique grâce à notre audit de niveau professionnel.")

# --- CONFIGURATION DE L'API ---
BASE_URL = "https://cyber-checker-audit.onrender.com"

# 📋 Fonction utilitaire bouton copier
def composant_bouton_copier(texte_a_copier, element_id):
    html_code = f"""
    <button id="btn_{element_id}" style="
        width: 100%; height: 38px; background-color: #262730; color: #FA;
        border: 1px solid #464855; border-radius: 4px; cursor: pointer;
        font-size: 14px; transition: all 0.2s ease;
    " onclick="
        navigator.clipboard.writeText('{texte_a_copier}');
        this.innerHTML = '📋 Copié !';
        this.style.backgroundColor = '#1c6337';
        this.style.borderColor = '#238636';
        setTimeout(() => {{
            this.innerHTML = '📋 Copier';
            this.style.backgroundColor = '#262730';
            this.style.borderColor = '#464855';
        }}, 2000);
    ">📋 Copier</button>
    """
    return st.html(html_code)

# Blindé contre les fuites sur GitHub
API_KEY = os.getenv("CLE_API_INTERNE")
if not API_KEY:
    raise RuntimeError("🚨 ERREUR CRITIQUE : La variable d'environnement 'CLE_API_INTERNE' est introuvable.")

headers = {"X-API-KEY": API_KEY}

# ==========================================
# 2. ESPACE D'ADMINISTRATION
# ==========================================
def afficher_panneau_admin(base_url):
    st.subheader("👨‍💻 Espace d'Administration Général")
    st.caption("Réservé exclusivement à l'administrateur. Autorisation validée par JWT.")
    
    if st.button("🔄 Charger la liste des utilisateurs"):
        with st.status("Interrogation de la base de données sécurisée...", expanded=True) as status:
            try:
                headers_admin = {"X-API-KEY": API_KEY, "Authorization": f"Bearer {st.session_state['session_jwt']}"}
                res = requests.get(f"{base_url}/admin/utilisateurs", headers=headers_admin)
                
                if res.status_code == 200:
                    data = res.json()
                    status.update(label="Données chargées !", state="complete", expanded=False)
                    st.success(f"Propriétaire : {data.get('PROPRIETAIRE', 'Admin')}")
                    st.metric("Total des utilisateurs inscrits", data.get("total_utilisateurs", 0))
                    st.dataframe(data.get("liste", []), use_container_width=True)
                else:
                    status.update(label="Accès refusé", state="error", expanded=True)
                    st.error(f"🛑 Accès refusé (Code {res.status_code}). Privilèges insuffisants.", icon="🔒")
            except Exception as e:
                status.update(label="Erreur de liaison", state="error", expanded=True)
                st.error("**Le serveur distant ne répond pas.** Vérifiez votre clé d'API.", icon="🚨")

# ==========================================
# 3. HUB D'AUDIT PUBLIC
# ==========================================
def afficher_hub_public():
    tab1, tab2 = st.tabs(["🔒 Audit Mot de Passe", "📧 Audit Fuite Email"])

    # --- ONGLET 1 : AUDIT MOT DE PASSE ---
    with tab1:
        st.subheader("Analyseur de Robustesse")
        pwd = st.text_input("Entrez un mot de passe à tester :", type="password", key="pwd_input")
        
        if st.button("Analyser le mot de passe", key="btn_pwd"):
            if pwd:
                with st.status("Analyse cryptographique en cours...", expanded=True) as status:
                    try:
                        payload = {"pwd": pwd, "lang": "Français"}
                        response = requests.post(f"{BASE_URL}/audit", json=payload, headers=headers)
                        
                        if response.status_code == 200:
                            data = response.json()
                            score, leaks = data["score"], data["pwned_leaks"]
                            status.update(label="Analyse terminée !", state="complete", expanded=False)
                            
                            if leaks > 0:
                                st.error(f"**Alerte critique : Ce mot de passe a été détecté dans {leaks} fuites !**", icon="⚠️")
                            elif score >= 3:
                                st.success("**Mot de passe hautement sécurisé.** Aucune fuite détectée.", icon="🛡️")
                            else:
                                st.warning("**Mot de passe intègre mais trop faible.**", icon="💡")
                            
                            col1, col2 = st.columns(2)
                            col1.metric("Score d'Entropie", f"{score}/4")
                            col2.metric("Fuites publiques", f"{leaks} fois")
                            
                            st.markdown("---")
                            st.markdown("#### 💡 Recommandations CyberBrain")
                            st.info(f"**Option A :** `{data['recommendation']['passphrase_suggestion']}`")
                            st.success(f"**Option B :** `{data['recommendation']['random_token']}`")
                            
                        elif response.status_code == 403:
                            status.update(label="Accès refusé", state="error", expanded=True)
                            st.error("**Clé d'API invalide.**", icon="🔒")
                        elif response.status_code == 429:
                            status.update(label="Serveur surchargé", state="error", expanded=True)
                            st.error("🛑 Trop de requêtes. Patientez 1 minute.", icon="⏳")
                        else:
                            status.update(label="Échec", state="error", expanded=True)
                            st.error(f"Erreur technique (Code {response.status_code}).")
                    except Exception:
                        status.update(label="Erreur réseau", state="error", expanded=True)
                        st.error("**Échec de communication avec le serveur.**", icon="🚨")
            else:
                st.warning("Veuillez saisir un mot de passe.")

    # --- ONGLET 2 : AUDIT EMAIL - FIX CRITIQUE POST JSON ---
    with tab2:
        st.subheader("Détecteur de Violations d'Identité")
        email = st.text_input("Entrez votre adresse email :", placeholder="exemple@domaine.com", key="email_input")
        
        if st.button("Scanner les bases de données", key="btn_email"):
            if email:
                if "@" not in email or "." not in email:
                    st.error("Le format de l'adresse email semble incorrect.", icon="📧")
                else:
                    with st.status("Scan mondial des piratages en cours...", expanded=True) as status:
                        try:
                            payload = {"email": email} # <-- 1. Body JSON
                            response = requests.post(f"{BASE_URL}/audit-email", json=payload, headers=headers) # <-- 2. POST au lieu de GET
                            
                            if response.status_code == 200:
                                data = response.json()
                                status_api = data["status"]
                                status.update(label="Scan finalisé.", state="complete", expanded=False)
                                
                                if status_api == "danger":
                                    st.error(f"**Violation détectée :** {data['message']}", icon="🚨")
                                    st.markdown("#### Sites impliqués :")
                                    for breach in data["details"]:
                                        st.write(f"• **{breach}**")
                                    st.warning("👉 **Action requise :** Changez immédiatement vos mots de passe.")
                                elif status_api == "clean":
                                    st.success(f"**Excellente nouvelle !** {data['message']}", icon="✅")
                                    st.balloons()
                                else:
                                    st.info(data["message"])
                                    
                            elif response.status_code == 403:
                                status.update(label="Échec auth", state="error", expanded=True)
                                st.error("**Clé d'API invalide.**", icon="🔒")
                            elif response.status_code == 429:
                                status.update(label="Serveur surchargé", state="error", expanded=True)
                                st.error("🛑 Trop de requêtes. Attendez 1 minute.", icon="⏳")
                            else:
                                status.update(label="Erreur inconnue", state="error", expanded=True)
                                st.error(f"Erreur technique (API) : {response.status_code}")
                        except Exception:
                            status.update(label="Échec du scan", state="error", expanded=True)
                            st.error("**Connexion au serveur compromise.**", icon="🚨")
            else:
                st.warning("Veuillez entrer une adresse email.")

# ==========================================
# 4. ÉCRAN D'AUTHENTIFICATION
# ==========================================
def afficher_ecran_auth(base_url, headers_api_globaux):
    st.subheader("🔐 Accès au Coffre-fort CyberBrain")
    
    choix_auth = st.radio("Que souhaitez-vous faire ?", ["Se connecter", "Créer un compte"], horizontal=True)
    
    with st.form(key="formulaire_authentification"):
        email = st.text_input("Adresse e-mail :", placeholder="nom@exemple.com")
        password = st.text_input("Mot de passe maître :", type="password", placeholder="••••••••••••")
        texte_bouton = "S'authentifier" if choix_auth == "Se connecter" else "Créer mon compte sécurisé"
        soumis = st.form_submit_button(label=texte_bouton, use_container_width=True)
        
    if soumis:
        if email and password:
            if choix_auth == "Se connecter":
                with st.status("Validation de vos accès...", expanded=True) as status:
                    try:
                        payload = {"email": email, "password": password}
                        response = requests.post(f"{base_url}/auth/connexion", json=payload, headers=headers_api_globaux)
                        
                        if response.status_code == 200:
                            data = response.json()
                            status.update(label="Identité confirmée !", state="complete", expanded=False)
                            st.session_state["logged_in"] = True
                            st.session_state["session_jwt"] = data["access_token"]
                            st.session_state["user_email"] = email.strip().lower()
                            st.rerun()
                        elif response.status_code in [401, 403]:
                            status.update(label="Accès refusé", state="error", expanded=True)
                            st.error("**Identifiants incorrects.**", icon="🔒")
                        else:
                            status.update(label="Erreur", state="error", expanded=True)
                            st.error("**Le serveur a rencontré un problème.**", icon="🚨")
                    except Exception:
                        status.update(label="Panne réseau", state="error", expanded=True)
                        st.error("**Impossible de joindre le serveur.**", icon="🚨")
            else:  # Créer un compte
                with st.status("Création de votre environnement...", expanded=True) as status:
                    try:
                        payload = {"email": email, "password": password}
                        response = requests.post(f"{base_url}/auth/inscription", json=payload, headers=headers_api_globaux)
                        
                        if response.status_code == 200:
                            status.update(label="Espace créé !", state="complete", expanded=False)
                            st.success("🚀 **Compte créé !** Passez sur 'Se connecter'.", icon="✅")
                        else:
                            status.update(label="Échec", state="error", expanded=True)
                            st.error(f"❌ **Erreur :** {response.json().get('detail', 'Email déjà utilisé.')}")
                    except Exception:
                        status.update(label="Erreur réseau", state="error", expanded=True)
                        st.error("**Impossible de joindre le service.**", icon="🚨")
        else:
            st.warning("Veuillez remplir tous les champs.")

# ==========================================
# 5. ESPACE COFFRE-FORT
# ==========================================
def afficher_coffre_fort(base_url, headers_api_globaux):
    st.markdown(f"### 🧠 Votre Coffre-fort (`{st.session_state['user_email']}`)")
    
    if st.button("🚪 Se déconnecter", use_container_width=True):
        st.session_state["logged_in"] = False
        st.session_state["session_jwt"] = None
        st.session_state["user_email"] = ""
        st.rerun()
        
    st.markdown("---")
    
    # --- SECTION A : AJOUTER ---
    with st.expander("➕ Ajouter un nouvel identifiant"):
        nom_site = st.text_input("Nom du site :")
        url_site = st.text_input("URL du site :", placeholder="https://...")
        identifiant = st.text_input("Identifiant / Nom d'utilisateur :")
        mdp = st.text_input("Mot de passe à enregistrer :", type="password")
        
        if st.button("Chiffrer et sauvegarder"):
            if nom_site and identifiant and mdp:
                with st.status("Chiffrement et transfert sécurisé...", expanded=True) as status:
                    try:
                        headers_requete = {"X-API-KEY": API_KEY, "Authorization": f"Bearer {st.session_state['session_jwt']}"}
                        payload = {"nom_site": nom_site, "url_site": url_site, "identifiant": identifiant, "mot_de_passe_a_stocker": mdp}
                        res = requests.post(f"{base_url}/coffre/ajouter", json=payload, headers=headers_requete)
                        if res.status_code == 200:
                            status.update(label="Enregistré !", state="complete", expanded=False)
                            st.success("✅ Identifiant ajouté.")
                            st.rerun()
                        else:
                            status.update(label="Échec", state="error", expanded=True)
                            st.error("Erreur lors de la sauvegarde.")
                    except Exception:
                        status.update(label="Erreur réseau", state="error", expanded=True)
                        st.error("Impossible de joindre le coffre-fort.")
            else:
                st.warning("Veuillez remplir les champs obligatoires.")

    # --- SECTION B : VISUALISER ---
    st.markdown("#### 🔑 Vos identifiants enregistrés")
    try:
        headers_requete = {"X-API-KEY": API_KEY, "Authorization": f"Bearer {st.session_state['session_jwt']}"}
        res = requests.get(f"{base_url}/coffre/liste", headers=headers_requete)
        
        if res.status_code == 200:
            comptes = res.json().get("comptes", [])
            if not comptes:
                st.info("Votre coffre-fort est vide.")
            else:
                for idx, compte in enumerate(comptes):
                    with st.container():
                        col1, col2, col_copie, col3 = st.columns([2, 2, 1, 1])
                        col1.markdown(f"**🌐 {compte['nom_site']}**\n*{compte['identifiant']}*")
                        
                        cle_unique = f"pwd_{idx}_{compte['nom_site']}"
                        col2.text_input("Mot de passe :", value=compte['mot_de_passe'], type="password", key=cle_unique, label_visibility="collapsed")
                        
                        with col_copie:
                            composant_bouton_copier(compte['mot_de_passe'], f"copy_{idx}")
                        
                        with col3:
                            if compte['url_site']:
                                st.markdown(f"[Accéder]({compte['url_site']})")
                        
                        audit_status = compte.get("audit_result", "🔍 Non audité")
                        if "❌" in audit_status or "Erreur" in audit_status: st.error(f"Alerte : {audit_status}", icon="🔑")
                        elif "⚠️" in audit_status: st.error(f"Statut : {audit_status}", icon="⚠️")
                        elif "✅" in audit_status: st.success(f"Statut : {audit_status}", icon="🛡️")
                        else: st.info(f"Statut : {audit_status}")
                        
                        id_item = compte.get("id")
                        if id_item:
                            col_b1, col_b2, _ = st.columns([1, 1, 2])
                            with col_b1: btn_mod = st.button("📝 Modifier", key=f"btn_mod_{id_item}")
                            with col_b2: btn_sup = st.button("🗑️ Supprimer", key=f"btn_sup_{id_item}")
                                
                            if btn_mod:
                                with st.form(key=f"form_mod_{id_item}"):
                                    st.markdown(f"#### 📝 Modifier : {compte['nom_site']}")
                                    nouveau_site = st.text_input("Nom du site", value=compte['nom_site'])
                                    nouvel_user = st.text_input("Identifiant", value=compte['identifiant'])
                                    nouveau_pass = st.text_input("Nouveau mot de passe", value=compte['mot_de_passe'], type="password")
                                    
                                    if st.form_submit_button("💾 Enregistrer"):
                                        payload_edit = {"nom_site": nouveau_site, "identifiant": nouvel_user, "mot_de_passe": nouveau_pass} # <-- Match ItemCoffreUpdate backend
                                        res_edit = requests.put(f"{base_url}/coffre/modifier/{id_item}", json=payload_edit, headers=headers_requete)
                                        if res_edit.status_code == 200:
                                            st.success("Modifié !")
                                            st.rerun()
                                        else:
                                            st.error(f"Échec de la modification. Code: {res_edit.status_code}")
                                            
                            if btn_sup:
                                st.warning(f"⚠️ Confirmer la suppression de {compte['nom_site']} ?")
                                col_c1, col_c2 = st.columns(2)
                                with col_c1:
                                    if st.button("✔️ Oui, Supprimer", key=f"conf_sup_{id_item}"):
                                        res_del = requests.delete(f"{base_url}/coffre/supprimer/{id_item}", headers=headers_requete)
                                        if res_del.status_code == 200:
                                            st.success("Supprimé !")
                                            st.rerun()
                                        else:
                                            st.error("Erreur serveur.")
                                with col_c2:
                                    st.button("❌ Annuler", key=f"cancel_{id_item}")

                        st.markdown("---")
                        
        elif res.status_code == 401:
            st.error("🔒 Session expirée. Reconnectez-vous.", icon="🔒")
            st.session_state["logged_in"] = False
            st.session_state["session_jwt"] = None
            st.session_state["user_email"] = ""
            st.rerun()
        else:
            st.error("Impossible d'accéder au coffre-fort.", icon="🚨")
    except Exception as e:
        st.error(f"Erreur réseau : {e}")

# ==========================================
# 6. NAVIGATION SIDEBAR
# ==========================================
st.sidebar.title("🧭 Navigation CyberBrain")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "go6axe4nh@mozmail.com").strip().lower()

liste_choix = ["🛡️ Hub d'Audit Public", "🔐 Mon Coffre-fort"]
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
st.caption("CyberBrain Security Suite v2.6 • Full Async • Propriété de l'Administrateur")
