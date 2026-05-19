import sqlite3
import os

DB_NAME = "cyberbrain_vault.db"

def init_db():
    """Initialise la base de données SQL de CyberBrain"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # 1. Création de la table des utilisateurs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS utilisateurs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        master_password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # 2. Création de la table du coffre-fort (mots de passe chiffrés)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS coffre_fort (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        nom_site TEXT NOT NULL,
        url_site TEXT,
        identifiant TEXT NOT NULL,
        mot_de_passe_chiffre TEXT NOT NULL, -- Chiffré en AES-256
        FOREIGN KEY (user_id) REFERENCES utilisateurs(id)
    )
    """)
    
    conn.commit()
    conn.close()
    print("🧠 Base de données CyberBrain initialisée avec succès !")

if __name__ == "__main__":
    init_db()