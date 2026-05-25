import psycopg2
import os

# Si la variable DATABASE_URL existe sur Render, on l'utilise. Sinon, on prend ta chaîne Supabase locale.
DB_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://postgres.siuwslfefkatmcsfwixh:25-05-26*SupaBase@@aws-0-eu-central-1.pooler.supabase.com:5432/postgres"
)

def get_db_connection():
    """Crée une connexion réseau directe vers PostgreSQL sur Supabase"""
    return psycopg2.connect(DB_URL)

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
    
    conn.commit()
    cursor.close()
    conn.close()
    print("🐘 Base de données PostgreSQL (Supabase) initialisée avec succès !")
