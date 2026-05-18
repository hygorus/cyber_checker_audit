import streamlit as st
import requests
import os

# Configuration de la page
st.set_page_config(page_title="CyberBrain Security Suite", page_icon="🧠", layout="centered")

st.title("🧠 CyberBrain : Hub de Sécurité")
st.write("Protégez votre identité numérique grâce à notre audit de niveau professionnel.")

# --- CONFIGURATION DE L'API ---
# Assure-toi que cette URL correspond bien à ton instance Render
BASE_URL = "https://cyber-checker-audit.onrender.com"
API_KEY = os.getenv("CLE_API_INTERNE", "CLE-YVES-PRO")

headers = {"X-API-KEY": API_KEY}

# --- CRÉATION DES ONGLETS ---
tab1, tab2 = st.tabs(["🔒 Audit Mot de Passe", "📧 Audit Fuite Email"])

# ==========================================
# ONGLET 1 : AUDIT MOT DE PASSE
# ==========================================
with tab1:
    st.subheader("Analyseur de Robustesse")
    pwd = st.text_input("Entrez un mot de passe à tester :", type="password", key="pwd_input")
    
    if st.button("Analyser le mot de passe", key="btn_pwd"):
        if pwd:
            with st.spinner("Analyse cryptographique en cours..."):
                try:
                    response = requests.get(f"{BASE_URL}/audit", headers=headers, params={"pwd": pwd, "lang": "Français"})
                    
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
                        
                        # Recommandations enrichies
                        st.markdown("---")
                        st.markdown("#### 💡 Recommandations CyberBrain")
                        
                        # Option 1 : La Passphrase mémorisable
                        st.info(f"**Option A (Facile à retenir) :** `{data['recommendation']['passphrase_suggestion']}`")
                        
                        # Option 2 : Le mot de passe ultra-complexe (Caractères divers)
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
                            breach_count = data["breach_count"]
                            
                            if status == "danger":
                                st.error(f"🚨 Alerte : {data['message']}")
                                st.markdown("#### Sites impliqués dans le piratage :")
                                # Affichage propre de la liste des sites compromis
                                for breach in data["details"]:
                                    st.write(f"• **{breach}**")
                                st.warning("👉 Action requise : Changez immédiatement les mots de passe des sites mentionnés.")
                            
                            elif status == "clean":
                                st.success(f"✅ Félicitations ! {data['message']}")
                                st.balloons() # Petite animation visuelle de victoire !
                                
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
