"""
Gestion sécurisée du mot de passe maître.

Utilise Argon2id conformément aux recommandations actuelles.
"""

from argon2 import PasswordHasher
from argon2.exceptions import (
    VerifyMismatchError,
    InvalidHash,
)

# Paramètres adaptés à une API Web.
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,   # 64 Mo
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hacher_mot_de_passe_maitre(password: str) -> str:
    """
    Retourne un hash Argon2id du mot de passe maître.
    """
    return _password_hasher.hash(password)


def verifier_mot_de_passe_maitre(
    password_propose: str,
    hash_stocke: str,
) -> bool:
    """
    Vérifie qu'un mot de passe correspond au hash enregistré.
    """
    try:
        return _password_hasher.verify(hash_stocke, password_propose)
    except (VerifyMismatchError, InvalidHash):
        return False


def hash_a_besoin_d_etre_mis_a_jour(hash_stocke: str) -> bool:
    """
    Indique si le hash doit être recalculé
    (par exemple après une augmentation
    des paramètres Argon2).
    """
    return _password_hasher.check_needs_rehash(hash_stocke)
