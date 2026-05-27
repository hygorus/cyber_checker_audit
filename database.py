import psycopg2
import os

# Récupération de l'URL propre de Render
DB_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    """Crée une connexion réseau directe vers PostgreSQL sur Supabase"""
    conn = psycopg2.connect(DB_URL)
    
    # 💡 LIGNE AJOUTÉE : Indispensable pour que Supabase accepte les requêtes de l'API
    conn.autocommit = True
    
    return conn

def init_db():
    """Initialise les tables indispensables dans PostgreSQL si elles n'existent pas"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Table Utilisateurs (Syntaxe Postgres avec SERIAL pour l'auto-incrément)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS utilisateurs (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        master_password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # 2. Table CoffreFort
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS coffre_fort (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        nom_site VARCHAR(255) NOT NULL,
        url_site VARCHAR(255),
        identifiant VARCHAR(255) NOT NULL,
        mot_de_passe_chiffre TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES utilisateurs(id) ON DELETE CASCADE
    );
    """)
    
    # Note : Plus besoin de conn.commit() ici car autocommit est activé au-dessus
    cursor.close()
    conn.close()
    print("🐘 Base de données PostgreSQL (Supabase) initialisée avec succès !")
