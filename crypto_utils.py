from cryptography.fernet import Fernet
import os

# Dans un vrai projet, cette clé doit être stockée dans tes variables d'environnement Render.
# Pour le développement local, si elle n'existe pas, on en génère une automatiquement.
SECRET_KEY = os.getenv("CYBERBRAIN_ENCRYPTION_KEY")
if not SECRET_KEY:
    # Génère une clé valide pour Fernet si elle n'est pas dans l'environnement
    SECRET_KEY = Fernet.generate_key().decode()

fernet = Fernet(SECRET_KEY.encode())

def chiffrer_mot_de_passe(mot_de_passe_clair: str) -> str:
    """Prend un mot de passe lisible et le transforme en texte chiffré illisible"""
    if not mot_de_passe_clair:
        return ""
    texte_chifbre_bytes = fernet.encrypt(mot_de_passe_clair.encode('utf-8'))
    return texte_chifbre_bytes.decode('utf-8')

def dechiffrer_mot_de_passe(mot_de_passe_chiffre: str) -> str:
    """Prend un texte chiffré de la base de données et redonne le mot de passe en clair"""
    if not mot_de_passe_chiffre:
        return ""
    texte_clair_bytes = fernet.decrypt(mot_de_passe_chiffre.encode('utf-8'))
    return texte_clair_bytes.decode('utf-8')