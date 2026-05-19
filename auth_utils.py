import hashlib

def hacher_mot_de_passe_maitre(password: str) -> str:
    """Génère un hash SHA-256 sécurisé pour le mot de passe maître"""
    # On utilise un "sel" fixe pour ce premier prototype afin de durcir le hash
    sel = "CyberBrain_Salt_Pro_2026!"
    mot_de_passe_sale = password + sel
    return hashlib.sha256(mot_de_passe_sale.encode('utf-8')).hexdigest()

def verifier_mot_de_passe_maitre(password_propose: str, hash_stocke: str) -> bool:
    """Compare un mot de passe proposé avec le hash présent dans la base de données"""
    return hacher_mot_de_passe_maitre(password_propose) == hash_stocke